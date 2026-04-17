/*
 * arinc665_rsa.c
 *
 * ARINC 665 / DO-200B — RSA signing for aircraft loadable software (ALSF).
 * Sources:
 *   - ARINC 665-3: Loadable Software Standards (AEEC, 2016)
 *   - RTCA DO-200B: Standards for Processing Aeronautical Data (2015)
 *   - RTCA DO-178C: Software Considerations in Airborne Systems (2011)
 *   - Airbus A350 / Boeing 787 Electronic Aircraft Software Distribution System (EASDS)
 *
 * Aircraft loadable software (ALS) includes:
 *   - Flight management system (FMS) databases (navigation data, performance)
 *   - Avionics firmware: IRS (inertial reference), radar, FMS, ACARS
 *   - Aircraft condition monitoring function (ACMF) software
 *   - Electronic flight bag (EFB) application software
 *   - Engine FADEC (Full Authority Digital Engine Control) software updates
 *   - Navigation database updates (Jeppesen/Navtech, 28-day cycle)
 *
 * ARINC 665-3 Part 7 defines digital signatures for loadable software:
 *   - The signature covers: software part number, data load identifier (DLI),
 *     cryptographic checksum, and the software itself
 *   - Algorithm specified: RSA-2048 or ECDSA P-256 (but RSA-2048 is predominant
 *     in deployed systems due to age of implementation)
 *
 * The trust chain:
 *   Airbus/Boeing/OEM signs updates with their aircraft manufacturer CA (RSA-2048)
 *   Airline maintenance receives signed packages from the OEM or database provider
 *   Aircraft Data Loading Unit (ADLU) or Portable Data Loading Unit (PDLU) verifies
 *   the signature before loading software onto the Line Replaceable Unit (LRU)
 *
 * Deployed in:
 *   - Airbus A320/A330/A350/A380 — Type B (airborne data loading over ARINC 429/664)
 *   - Boeing 737 MAX/787/777X — similar ALSF architecture
 *   - Jeppesen NavDB updates (RSA-2048 signed, 28-day cycle, every airline worldwide)
 *
 * DO-178C DAL A software (most critical, direct effect on aircraft safety) uses
 * the same ARINC 665 loading mechanism with RSA signature verification.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* ARINC 665 Software Part (SWP) header */
struct arinc665_swp_header {
    uint8_t  arinc_file_type[4];      /* "ARINC" magic */
    uint32_t format_version;          /* 665-3 = 3 */
    uint8_t  part_number[20];         /* e.g., "8MA12P1015-03" (FMS nav DB) */
    uint8_t  data_load_identifier[8]; /* DLI: identifies the LRU target */
    uint32_t software_length;
    uint8_t  crc32[4];                /* CRC-32 of software body (legacy integrity) */
    uint32_t signature_offset;        /* offset to RSA signature in this file */
    uint32_t signature_length;        /* 256 for RSA-2048 */
    uint8_t  cert_der[2048];          /* DER-encoded signing certificate (RSA-2048) */
};

/*
 * arinc665_verify_software() — verify RSA-2048 signature on aircraft loadable software.
 *
 * Called by the ADLU (Aircraft Data Loading Unit) or PDLU before loading
 * any software onto an avionics Line Replaceable Unit (LRU).
 *
 * For DO-178C DAL A software (flight critical): this verification is mandatory.
 * The ADLU must reject software with invalid or missing signatures.
 *
 * An attacker who can forge the RSA-2048 signature can load arbitrary software
 * onto aircraft avionics LRUs. Depending on the target LRU, this could affect:
 *   - Flight management (FMS): navigation guidance, VNAV, lateral nav
 *   - Engine FADEC: thrust control, fuel metering, engine limits
 *   - IRS/ADIRU: attitude, heading, air data (affects every flight control system)
 */
int
arinc665_verify_software(const uint8_t *swp_image, size_t swp_len,
                          X509 *oem_ca_cert)
{
    const struct arinc665_swp_header *hdr;
    const uint8_t *sw_body;
    size_t sw_body_len;
    uint8_t digest[32];
    const uint8_t *cert_p;
    X509 *signing_cert = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    const uint8_t *sig;
    int ret = -1;

    if (swp_len < sizeof(struct arinc665_swp_header)) return -1;

    hdr = (const struct arinc665_swp_header *)swp_image;
    sw_body = swp_image + sizeof(*hdr);
    sw_body_len = hdr->software_length;

    /* SHA-256 of software body (ARINC 665-3 Part 7 specifies SHA-256 with RSA) */
    SHA256(sw_body, sw_body_len, digest);

    /* Decode signing certificate from SWP header */
    cert_p = hdr->cert_der;
    signing_cert = d2i_X509(NULL, &cert_p, sizeof(hdr->cert_der));
    if (!signing_cert) return -1;

    /* Verify certificate chains to OEM CA (Airbus/Boeing/Jeppesen PKI) */
    store = X509_STORE_new();
    X509_STORE_add_cert(store, oem_ca_cert);
    verify_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(verify_ctx, store, signing_cert, NULL);
    if (X509_verify_cert(verify_ctx) != 1) goto out;

    /* Locate RSA-2048 signature in SWP file */
    if (hdr->signature_offset + hdr->signature_length > swp_len) goto out;
    sig = swp_image + hdr->signature_offset;

    /* Verify RSA-2048 PKCS#1 v1.5 signature */
    pubkey = X509_get_pubkey(signing_cert);
    ctx = EVP_MD_CTX_new();

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) goto out;
    if (EVP_DigestVerifyUpdate(ctx, digest, 32) <= 0) goto out;

    /* 1 = valid — ADLU loads software onto LRU
     * 0 = forged — ADLU must reject and alert maintenance
     * Unless attacker can forge this, software cannot be loaded onto the LRU */
    ret = EVP_DigestVerifyFinal(ctx, sig, hdr->signature_length);

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509_free(signing_cert);
    return ret;
}

/*
 * jeppesen_navdb_verify() — verify Jeppesen navigation database RSA signature.
 *
 * Jeppesen/Boeing provides navigation database updates every 28 days (AIRAC cycles)
 * to every FMS-equipped aircraft worldwide. Each NavDB update is signed with
 * Jeppesen's RSA-2048 signing key.
 *
 * The NavDB contains:
 *   - Waypoints, VORs, ILS approaches (navigational aids)
 *   - SIDs, STARs, approach procedures
 *   - Airport/runway data
 *   - Airspace boundaries, restricted areas
 *
 * Every airline in the world installs Jeppesen NavDB updates on their FMS fleet
 * every 28 days. The FMS verifies the RSA-2048 signature before accepting the data.
 *
 * Forging a NavDB signature would allow loading navigation data that:
 *   - Incorrectly places ILS localizer frequencies
 *   - Modifies approach minima
 *   - Contains false waypoint coordinates
 *   - Alters missed approach procedures
 *
 * Not the same as "hack the plane" — the crew and other systems provide redundancy —
 * but incorrect navigation data in the FMS has contributed to incidents historically.
 */
int
jeppesen_navdb_verify(const uint8_t *navdb_data, size_t navdb_len,
                       const uint8_t *signature, size_t sig_len,
                       X509 *jeppesen_ca_cert)
{
    /* Same RSA-2048 PKCS#1 v1.5 verify as above — just with Jeppesen's CA */
    EVP_PKEY *jeppesen_pubkey = X509_get_pubkey(jeppesen_ca_cert);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;

    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, jeppesen_pubkey);
    EVP_DigestVerifyUpdate(ctx, navdb_data, navdb_len);
    ret = EVP_DigestVerifyFinal(ctx, signature, sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(jeppesen_pubkey);
    return ret;
}
