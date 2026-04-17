/*
 * desktop_login_flow.c
 *
 * Windows / Linux desktop interactive login against a PIV or CAC
 * smartcard. Surrounds the RSA-based on-card primitive
 * (`opensc_piv_rsa.c`) with the real sign-in experience: card insert
 * detection, CCID reader APDU bring-up, PIN dialog, PIV Application
 * Data Object (PIV Authentication Key, slot 9A) challenge/response,
 * Kerberos PKINIT handoff, and the RADIUS-over-TLS gateway path that
 * network admission controllers (Cisco ISE, Aruba ClearPass) use to
 * bounce cert validity against enterprise OCSP responders.
 *
 * Deployed across:
 *   - DoD CAC (Common Access Card) — ~3.5M active CACs, used on
 *     NIPRNET / DoD JWICS for desktop logon
 *   - Federal PIV per HSPD-12 (treasury, state, USDA, VA, DHS...)
 *   - DoE SafeGuards PIV-I interoperable cards
 *   - State/local gov PIV-I (NYC ID, NJ CourtSecure)
 *   - Enterprise PIV-C rollouts (Fortune-500 contractors, major
 *     banks, pharma)
 */

#include <winscard.h>
#include "piv_card.h"
#include "opensc_piv_rsa.h"


int
desktop_piv_interactive_login(void)
{
    /* 1. Card insert event — WinSCard.SCardGetStatusChange or
     *    pcsc-lite equivalent.  UI (LogonUI on Windows, polkit +
     *    gdm on GNOME, lightdm on KDE, sssd-pac on Linux with
     *    sssd-ssh) pops the card prompt. */
    wait_for_card_insert();

    /* 2. SELECT PIV Application AID (A0 00 00 03 08 00 00 10 00 01 00). */
    piv_select_piv_aid();

    /* 3. Read cert from container 9A (PIV Authentication certificate).
     *    Chain extends through the agency intermediate to the
     *    Federal PKI Common Policy Root CA G2 (RSA-4096). */
    uint8_t piv_cert_der[4096]; size_t piv_cert_len;
    piv_read_certificate(0x9A, piv_cert_der, &piv_cert_len);

    /* 4. Verify chain against the machine's local trust anchors:
     *    Windows "NTAuth" store + Federal Common Policy bundle,
     *    or Linux /etc/pki/tls/certs with the FPKIPA bundle. */
    if (verify_piv_cert_chain(piv_cert_der, piv_cert_len) != 0) {
        return LOGIN_DENIED_CERT_INVALID;
    }

    /* 5. Check revocation. Card logon pushes OCSP through the
     *    machine's network config (the DoD uses OCSP responders
     *    operated by DISA). Status is cached per-cert for the
     *    nextUpdate window. */
    if (piv_ocsp_check(piv_cert_der, piv_cert_len) != PIV_OCSP_GOOD) {
        return LOGIN_DENIED_REVOKED;
    }

    /* 6. PIN entry + VERIFY APDU. Lockout after 3 wrong PINs for
     *    CAC, 6 for PIV (per FIPS 201). */
    char pin[9];
    pin_dialog_blocking(pin, sizeof pin);
    if (piv_verify_pin(pin, strlen(pin)) != 0) {
        return LOGIN_DENIED_BAD_PIN;
    }

    /* 7. GENERAL AUTHENTICATE challenge: sign a dynamic 256-byte
     *    random from the AD KDC (or local Kerberos) using the on-
     *    card RSA-2048 private key in slot 9A. This is the RSA
     *    primitive the whole ceremony rests on. */
    uint8_t challenge[256], signature[256];
    kdc_fetch_pkinit_challenge(challenge);
    if (opensc_piv_rsa_sign_slot9a(challenge, sizeof challenge,
                                     signature, sizeof signature) != 0) {
        return LOGIN_DENIED_CARD_ERROR;
    }

    /* 8. Complete PKINIT pre-auth: bundle the signature into a
     *    PA-PK-AS-REQ (see ../kerberos-pkinit/ directory for the
     *    KDC-side handler), receive a TGT, derive reply-key,
     *    materialize the Windows LSA session + user profile. */
    if (pkinit_complete(piv_cert_der, piv_cert_len, signature) != 0) {
        return LOGIN_DENIED_PKINIT_FAIL;
    }

    /* 9. Tell Cisco ISE / Aruba ClearPass to bind the 802.1X
     *    session (EAP-TLS or TEAP) to the just-logged-in user —
     *    same cert drove both EAP-TLS and PKINIT. */
    notify_nac_session_mapping(piv_cert_der);

    return LOGIN_SUCCESS;
}


/* ---- Breakage ----
 *
 * The Federal PKI Common Policy Root CA G2 (RSA-4096) signs every
 * agency intermediate that signs every PIV card's Authentication
 * Certificate. A factoring attack against G2 is one of the highest-
 * impact cryptographic catastrophes on the planet:
 *   - Every federal + DoD workstation logon becomes impersonable
 *     — attackers mint a PIV auth cert mapping to any federal
 *     employee, walk through PKINIT, land on their desktop.
 *   - Every NIPRNET / DoD portal that requires CAC auth falls to
 *     the same primitive.
 *   - Federal PKI cross-certifies to Adobe Approved Trust List,
 *     DigiCert's federated bridges, and the Adobe/Microsoft
 *     document trust chains — so a G2 factoring break is *also* a
 *     cross-industry commercial trust catastrophe.
 * This is why NIST CSRC lists CA migration off RSA as the single
 * highest-priority PQC initiative for the federal-civilian + DoD
 * identity ecosystem.
 */
