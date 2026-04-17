/*
 * osnma_receiver_verify.c
 *
 * Galileo OSNMA receiver-side verification. Runs inside the GNSS
 * baseband firmware on every u-blox F9P, Septentrio mosaic-X5,
 * STMicro Teseo-V, Broadcom BCM47758 chip that exposes
 * OSNMA-authenticated PVT.
 *
 * Two signature paths:
 *   - DSM-KROOT: RSA-signed TESLA root-key announcement, verified
 *     against the GSA signing CA pubkey pinned in firmware.
 *   - DSM-PKR:   RSA-signed Merkle-tree public-key renewal.
 *
 * TESLA MAC chain verification is HMAC-SHA256 (or CMAC-AES), but
 * the *chain anchor* reaches back to a GSA-CA RSA signature.
 */

#include <stdint.h>
#include <string.h>
#include "osnma.h"
#include "rsa_pkcs1_pss.h"
#include "merkle_tree.h"

/* 256-byte RSA-2048 DS, 384-byte RSA-3072 DS, 512-byte RSA-4096 DS.
 * OSNMA ICD permits up to RSA-4096. */
struct dsm_kroot_msg {
    uint8_t  nma_header;         /* NMA Status, chain ID, CPKS */
    uint8_t  kroot[32];          /* root key for the TESLA chain */
    uint32_t gst_applicable;     /* Galileo System Time of validity */
    uint8_t  padding[13];
    uint8_t  ds[512];            /* digital signature, len = key size */
};

struct dsm_pkr_msg {
    uint8_t  mid[4];             /* Merkle tree ID */
    uint8_t  itn[32];            /* intermediate node path */
    uint8_t  npkt;               /* New Public Key Type */
    uint8_t  new_public_key[64]; /* ECDSA-P256 / P521 new signing key */
    uint8_t  ds[512];            /* RSA signature by GSA CA */
};

/* Pinned at manufacture / firmware update time. */
extern const uint8_t GSA_CA_RSA_PUBKEY_DER[];
extern const size_t  GSA_CA_RSA_PUBKEY_DER_LEN;

int osnma_verify_dsm_kroot(const struct dsm_kroot_msg *m, size_t ds_len)
{
    uint8_t hash[32];
    /* Hash covers nma_header || kroot || gst_applicable || padding. */
    sha256_of(&m->nma_header, offsetof(struct dsm_kroot_msg, ds), hash);
    return rsa_pkcs1_pss_verify(
        GSA_CA_RSA_PUBKEY_DER, GSA_CA_RSA_PUBKEY_DER_LEN,
        hash, sizeof hash,
        m->ds, ds_len);
}

int osnma_verify_dsm_pkr(const struct dsm_pkr_msg *m, size_t ds_len)
{
    uint8_t hash[32];
    sha256_of(m, offsetof(struct dsm_pkr_msg, ds), hash);

    /* Merkle-path check: reconstruct root from leaf(new_public_key)
     * + intermediate nodes, compare against pinned MTPK root. */
    if (!merkle_verify_path(m->mid, m->itn,
                             m->new_public_key, sizeof m->new_public_key))
        return -1;

    return rsa_pkcs1_pss_verify(
        GSA_CA_RSA_PUBKEY_DER, GSA_CA_RSA_PUBKEY_DER_LEN,
        hash, sizeof hash,
        m->ds, ds_len);
}

/* Per-subframe TESLA MAC check (called at 30 Hz per satellite in view). */
int osnma_verify_tesla_mac(const uint8_t *nav_subframe, size_t len,
                           const uint8_t *mac, uint8_t key_index)
{
    uint8_t derived_key[32];
    if (tesla_derive_key(key_index, derived_key) < 0) return -1;

    uint8_t expected[32];
    hmac_sha256(derived_key, sizeof derived_key,
                 nav_subframe, len, expected);
    return constant_time_memcmp(expected, mac, 32);
}

/* Receiver boot path
 *
 *   1. Load pinned GSA-CA pubkey from OTP / signed firmware image.
 *   2. On first sync to E1-B: collect DSM-KROOT frames (~6 minutes
 *      of accumulation), reassemble, verify RSA signature.
 *   3. On success, mark OSNMA status = "Authenticated"; start
 *      forwarding the OSNMA flag into NMEA-0183 / UBX / SBF output
 *      so downstream autopilot, ECDIS, ADAS consumes the bit.
 *   4. On TESLA chain rollover: wait for DSM-PKR, verify RSA+Merkle,
 *      adopt new public key as next-chain anchor.
 *   5. On failure at any step: set OSNMA status = "Not Authenticated",
 *      optionally fall back to unauthenticated GPS or refuse PVT fix
 *      per host-application policy.
 *
 * ---- Breakage ----
 *
 * Factoring the GSA signing CA pubkey lets an attacker broadcast a
 * forged DSM-KROOT over any Galileo-E1-B-band spoof transmitter
 * (commodity SDR + GNSS simulator). The receiver accepts attacker-
 * controlled TESLA keys, authenticates spoofed navigation messages,
 * reports PVT + OSNMA=Authenticated to the host. Consumers:
 *
 *   - An autonomous car drifts across a lane or into oncoming
 *     traffic while its safety-case-compliant GNSS reports "verified".
 *   - A maritime ECDIS shows a false fix in busy shipping lanes.
 *   - Smart-grid PMUs slew their timestamps enough to corrupt
 *     fault-location algorithms at substation scale.
 *   - 5G BTSs lose authenticated time sync, cascading through
 *     whole-country mobile-voice-call timing failures.
 *
 * Unlike terrestrial PKI there is no OCSP, no CRL, no out-of-band
 * recovery for an in-orbit / ground-segment key compromise short
 * of firmware-level rekey across every installed receiver.
 */
