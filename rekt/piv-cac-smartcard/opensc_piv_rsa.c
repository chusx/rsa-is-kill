/* Source: OpenSC/OpenSC src/libopensc/card-piv.c + pkcs15-piv.c
 *
 * PIV (Personal Identity Verification, FIPS 201) is the US federal government
 * identity standard. PIV cards (smart cards) are issued to all federal
 * employees and contractors — ~5 million cards in active use.
 *
 * CAC (Common Access Card) is the DoD military version — ~3.5 million active.
 * Together: ~8.5 million US government identity credentials, all RSA-2048.
 *
 * PIV card cryptographic slots (FIPS 201-3):
 *   Slot 9A — PIV Authentication (RSA-2048 or ECC P-256/P-384)
 *   Slot 9C — Digital Signature (RSA-2048 or ECC P-256/P-384)
 *   Slot 9D — Key Management (RSA-2048 or ECC P-256/P-384)
 *   Slot 9E — Card Authentication (RSA-2048 or ECC P-256/P-384)
 *
 * Default at issuance: RSA-2048 for all slots.
 * FIPS 201-3 added ECC support in 2022, but migration from RSA is not mandated.
 * No PQC algorithm is defined in FIPS 201-3 or SP 800-73-4 (PIV interfaces).
 *
 * PIV cards are used for:
 *   - US federal employee logical access (Windows login, SSH, VPN)
 *   - PIV-I (Interoperable): state/local government, contractors
 *   - FASC-N (Federal Agency Smart Credential Number) physical access
 */

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright (C) 2007, EMC, Russell Larner */

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"

/* PIV algorithm IDs (SP 800-73-4 Table 5) */
#define PIV_ALG_RSA_1024   0x06   /* RSA 1024-bit — legacy, some old CACs */
#define PIV_ALG_RSA_2048   0x07   /* RSA 2048-bit — dominant deployment */
#define PIV_ALG_ECC_P256   0x11   /* ECDSA P-256 — newer cards */
#define PIV_ALG_ECC_P384   0x14   /* ECDSA P-384 */
/* PIV_ALG_ML_DSA — NOT DEFINED in SP 800-73-4 */
/* PIV_ALG_SLH_DSA — NOT DEFINED */

/* OpenSC PIV card capabilities flags */
#define CI_NO_RSA2048      0x00010000U  /* card lacks RSA-2048 (very old) */
#define CI_RSA_4096        0x00080000U  /* card supports RSA-4096 (rare) */

/*
 * piv_general_authenticate() — perform an asymmetric crypto operation on the card.
 * This is called for TLS client authentication, S/MIME signing, code signing, etc.
 *
 * @alg_id:  PIV_ALG_RSA_2048 (0x07) for the vast majority of deployed cards
 * @key_ref: 0x9A (auth), 0x9C (signature), 0x9D (key management), 0x9E (card auth)
 *
 * The private key never leaves the card. The modulus (public key) is in the
 * corresponding certificate stored in slot 0x5FC105 (9A cert), etc.
 * A CRQC recovers the private key from the certificate public key.
 */
static int piv_general_authenticate(sc_card_t *card,
                                     unsigned int key_ref,
                                     unsigned int alg_id)  /* typically PIV_ALG_RSA_2048 */
{
    size_t key_len;
    EVP_CIPHER *cipher;
    uint8_t *key;

    /* Get key length from alg_id */
    switch (alg_id) {
    case PIV_ALG_RSA_1024: key_len = 128; break;
    case PIV_ALG_RSA_2048: key_len = 256; break;   /* 256 bytes = 2048 bits */
    case PIV_ALG_ECC_P256:  key_len = 32;  break;
    case PIV_ALG_ECC_P384:  key_len = 48;  break;
    default: return SC_ERROR_NOT_SUPPORTED;
    }

    /* Build GENERAL AUTHENTICATE APDU and send to card */
    /* Response: RSA signature or ECDH shared secret */
    return piv_general_io(card, 0x87, alg_id, key_ref,
                          sbuf, p - sbuf, rbuf, sizeof(rbuf));
}

/*
 * PIV certificate structure in OpenSC (pkcs15-piv.c):
 * Key algorithm determined at card initialization by reading
 * the X.509 certificate from each slot and checking the SubjectPublicKeyInfo.
 *
 * case 0x07: keydata->key_bits = 2048; break;  ← RSA-2048 (most PIV cards)
 *
 * NIST SP 800-131A Rev 2 (2019) disallows RSA-1024 for all federal use.
 * NIST SP 800-131A Rev 3 (expected 2025) will deprecate RSA-2048 for new use.
 * But migration requires: new cards issued, door reader firmware updated,
 * Windows Hello for Business and Active Directory updated, and middleware
 * (minidriver, OpenSC) updated to support PQC algorithms.
 */

/*
 * PIV card issuers (US federal):
 *   GSA USAccess — issues to most civilian agencies
 *   DoD CAC — issued by Defense Manpower Data Center
 *   State/Local PIV-I — issued by state governments
 *
 * FIPS 201-3 (2022) added ML-DSA as a future option in an appendix,
 * but SP 800-73-5 (the interface spec) has not been published with
 *  PQC algorithm IDs. No PIV card currently supports PQC.
 * GSA has not announced a PQC PIV card procurement timeline.
 */
