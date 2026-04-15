"""
evcc_secc_session.py

ISO 15118-2 / -20 Plug & Charge (PnC) session orchestration between an
EV (EVCC, Electric Vehicle Communication Controller — the onboard
charging computer) and a DC fast charger (SECC, Supply Equipment
Communication Controller). Wraps the TLS handshake and the contract
certificate chain validation whose RSA primitives live in
`iso15118_tls_auth.py`.

Every CCS / CharIN compliant DC fast-charge session runs this flow:
  - EV side: Volkswagen MEB, Tesla Model 3/Y/S/X (NACS bridge to CCS),
    Hyundai Ioniq 5/6, Kia EV6/EV9, Ford Mach-E, Polestar 2, BMW iX,
    Mercedes EQS, GM Ultium, Rivian, Lucid
  - Charger side: IONITY, Electrify America, EVgo, ChargePoint Express,
    Tesla Supercharger (v4 with CCS adapter), Fastned, Allego, Instavolt,
    BP Pulse, Shell Recharge

V2G Root CA: the CharIN-operated RSA-2048 trust root. OEM Sub-CAs
(VW OEM Sub CA, Tesla OEM Sub CA, Hyundai Sub CA...) issue the
contract certs under PnC billing agreements.
"""

from iso15118_tls_auth import (
    open_tls_channel,             # TLS 1.3 + RSA-PSS peer auth
    validate_contract_chain,      # contract cert ← OEM ← V2G Root
    verify_oem_provisioning_cert, # pre-PnC: OEM prov cert bootstrap
    sign_metering_receipt,        # EV signs final kWh receipt
)


class EVCC:
    """Onboard charging controller state machine."""

    def __init__(self, vehicle_id: str, contract_cert_bundle,
                  oem_prov_cert, v2g_root_certs):
        self.vehicle_id     = vehicle_id
        self.contract       = contract_cert_bundle   # EMAID-scoped cert + priv
        self.oem_prov       = oem_prov_cert          # factory cert from OEM Sub CA
        self.v2g_roots      = v2g_root_certs

    def start_pnc_session(self, secc_endpoint: str):
        # 1. SDP (SECC Discovery Protocol) — UDP IPv6 multicast → SECC
        #    replies with its TCP/TLS port.
        tls = open_tls_channel(secc_endpoint, self.oem_prov,
                                peer_must_chain_to=self.v2g_roots)
        if tls is None:
            raise RuntimeError("SECC TLS handshake failed")

        # 2. SessionSetupReq/Res — exchange EVCCID, receive session ID.
        tls.send_xml(self._session_setup_req())
        sess = tls.recv_xml()

        # 3. ServiceDiscoveryReq → charger advertises PnC / tariff
        #    service. EVCC selects PnC.
        tls.send_xml(self._service_discovery_req())
        tls.recv_xml()

        # 4. PaymentDetailsReq: EVCC sends its *contract* cert chain
        #    (leaf → MO Sub CA → V2G Root MO) separately from the TLS
        #    handshake. SECC verifies under V2G MO Root and maps EMAID
        #    → billing account at the eMSP (Elli, Plugsurfing, Hubject
        #    OCPI roaming, ChargePoint, EVgo).
        tls.send_xml(self._payment_details_req_with_contract_cert())
        pd_resp = tls.recv_xml()

        # 5. AuthorizationReq: EVCC signs a challenge using the
        #    *contract* RSA private key (under RSA-PSS-SHA256).
        #    Verifies EVCC is the legitimate holder of the contract
        #    cert, not just in possession of the public side.
        tls.send_xml(self._authz_req_rsa_sign(pd_resp["GenChallenge"]))
        tls.recv_xml()

        # 6. ChargeParameterDiscovery → CableCheck → PreCharge → bulk
        #    current regulation. These are signal-level (CAN + PWM)
        #    during the bulk charge, not XML; TLS sits idle.
        self._run_dc_charge_loop(tls)

        # 7. MeteringReceipt: SECC sends a signed consumption record;
        #    EVCC counter-signs with contract RSA private key; the
        #    signed receipt is what billing settles against at the
        #    eMSP. Signed receipts are non-repudiable and used in
        #    billing disputes.
        tls.send_xml(self._signed_metering_receipt(tls.recv_xml()))
        tls.close()


# ---- Breakage ----
#
# V2G PKI is a three-tier hierarchy (Root → OEM/MO/CPS Sub-CA → leaf).
# Roots: one per "domain" — V2G Root Mobility Operator, Charge Point
# Operator, OEM. All RSA-2048 as of 2026. A factoring attack on any of
# these roots lets an attacker:
#   - Forge contract certs → charge at any PnC station and bill an
#     arbitrary customer's eMSP account.
#   - Forge charger certs → bring up a rogue charger that vehicles
#     engage PnC with; harvest vehicle EMAIDs + contract credentials
#     for wider abuse.
#   - Forge OEM provisioning certs → enroll counterfeit vehicles
#     into the PnC ecosystem.
# The CharIN Hubject CA hierarchy is a single point of failure for
# European EV roaming billing.
