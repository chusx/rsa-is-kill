"""
rsp_sm_dp_plus_profile_download.py

GSMA SGP.22 Consumer RSP profile-download orchestration, driven from
the LPA (Local Profile Assistant) side — the app embedded on every
consumer phone (iOS eSIM setup flow, Android EuiccService,
Samsung/Pixel native LPA), tablet, wearable, automotive head-unit,
and IoT module (Quectel, Thales MFF2) that supports eSIM.

Interacts with an SM-DP+ server — operated by Thales, IDEMIA, Giesecke+
Devrient, Valid, Kigen, or carrier in-house (Airtel, Reliance, Jio,
Vodafone, DT/T-Mobile, AT&T, Verizon, KDDI, SoftBank, China Mobile) —
to fetch and bind an operational profile to a specific eUICC.

The RSA crypto primitives (RSP PKI, ECKA key agreement blended with
RSA signatures, profile protection key derivation) live in
`esim_rsa_provisioning.py`.
"""

import base64
import requests
from esim_rsa_provisioning import (
    verify_server_cert_chain,
    sign_euicc_challenge,
    decrypt_bound_profile_package,
)


class LPA:
    """Local Profile Assistant — in-device consumer RSP driver."""

    def __init__(self, euicc_handle, gsma_ci_roots):
        self.euicc = euicc_handle            # APDU interface to eUICC chip
        self.gsma_ci_roots = gsma_ci_roots   # GSMA CI Root (RSA-2048) bundle

    # -- triggered by ES9+.InitiateAuthentication from the Activation Code --
    def download_profile(self, sm_dp_plus_url: str, activation_code_token: str,
                          confirmation_code: str | None = None):
        session = requests.Session()
        session.headers["X-Admin-Protocol"] = "gsma/rsp/v2.2.0"

        # 1. initiateAuthentication: LPA sends the eUICC challenge +
        #    eUICC info (EID, SVN, Cert, supported capabilities). The
        #    SM-DP+ replies with its own certificate chain + server
        #    challenge signed under its RSA key.
        euicc_challenge = self.euicc.get_euicc_challenge()
        euicc_info1     = self.euicc.get_euicc_info1()
        r = session.post(f"{sm_dp_plus_url}/gsma/rsp2/es9plus/initiateAuthentication",
                         json={
                             "euiccChallenge": base64.b64encode(euicc_challenge).decode(),
                             "euiccInfo1":     base64.b64encode(euicc_info1).decode(),
                             "smdpAddress":    sm_dp_plus_url,
                         }, timeout=30)
        r.raise_for_status()
        resp = r.json()

        # 2. Verify the SM-DP+ cert chain under the pinned GSMA CI
        #    root (this is the factoring-attack-surface). Server's
        #    signed response is RSA over the concatenation of the
        #    challenges.
        if not verify_server_cert_chain(
                resp["serverCertificate"],
                resp["serverSigned1"],
                resp["serverSignature1"],
                self.gsma_ci_roots):
            raise RuntimeError("SM-DP+ chain verification failed")

        # 3. eUICC signs the server's data inside the chip using its
        #    factory-provisioned RSA key (issued by an EUM CA chained
        #    to GSMA CI Root at chip manufacture time).  Returns an
        #    authenticateServerResponse TLV that the SM-DP+ verifies
        #    back.
        auth_server_resp = sign_euicc_challenge(self.euicc, resp)

        # 4. authenticateClient -> getBoundProfilePackage.
        r = session.post(f"{sm_dp_plus_url}/gsma/rsp2/es9plus/authenticateClient",
                         json={"authenticateServerResponse": auth_server_resp,
                               "transactionId": resp["transactionId"]},
                         timeout=30)
        r.raise_for_status()
        ack = r.json()

        # 5. Confirmation code (CC) binding — if operator requires it
        #    (post-paid activation, port-in flows).
        prepare_args = {"transactionId": resp["transactionId"]}
        if confirmation_code:
            prepare_args["confirmationCode"] = self.euicc.hash_cc(
                confirmation_code, resp["transactionId"])
        r = session.post(f"{sm_dp_plus_url}/gsma/rsp2/es9plus/getBoundProfilePackage",
                         json=prepare_args, timeout=60)
        r.raise_for_status()
        bpp = r.json()["boundProfilePackage"]

        # 6. BPP (Bound Profile Package) — a BER-TLV blob targeted to
        #    this eUICC by key agreement + derived wrapping keys, then
        #    APDU-scripted into the eUICC ISD-P. The eUICC verifies
        #    BPP integrity under the SM-DP+ RSA signature before
        #    committing.
        decrypt_bound_profile_package(self.euicc, bpp)

        # 7. Enable the profile, send ES9+.HandleNotification ACK.
        self.euicc.enable_profile_and_refresh()


# Reality: a factoring break on the GSMA CI Root (one of RSA-2048 / the
# newer -4096 key series operated by GSMA) allows an attacker to:
#   - Impersonate any SM-DP+ to any eUICC, pushing arbitrary profiles
#     with forged server certs.
#   - Forge EUM certs and bring counterfeit eUICCs online on live
#     operator networks.
#   - Hijack the eSIM activation flow for Apple/Google/Samsung fleets
#     — silently swap a victim's eSIM onto an attacker-held profile
#     and intercept SMS-OTP for their bank / email / crypto accounts.
# The CI Root is the single most consequential RSA key in the global
# mobile-identity supply chain — it signs the trust anchors of every
# operator eSIM service worldwide.
"""
