/*
 * bac_pa_active_auth.c
 *
 * ICAO Doc 9303 ePassport — BAC session + Passive
 * Authentication + Active Authentication. The full chain
 * from contactless swipe to identity assertion.
 *
 * BAC (Basic Access Control) uses a 3DES key derived from
 * MRZ data; PA (Passive Authentication) then verifies the
 * signed data groups (DG1..DG16) against the DS (Document
 * Signer) certificate, which chains to the CSCA (Country
 * Signing CA). CSCAs are RSA-2048/4096, published in the
 * ICAO PKD. Active Auth uses the chip's on-board RSA key to
 * prove liveness (anti-cloning).
 *
 * There are ~1.5 billion active ePassports; every CSCA is RSA.
 */

#include <stdint.h>
#include <string.h>
#include "icao.h"

extern const uint8_t CSCA_PUB[];       /* per country, PKD      */
extern size_t CSCA_PUB_LEN;

/* EF.SOD — the Security Object Document. An ASN.1 SignedData
 * (CMS, RFC 5652) wrapping the LDS Security Object which
 * contains hashes of all Data Groups on the chip. */
struct ef_sod {
    uint8_t  ds_cert[2048]; size_t ds_cert_len;  /* Document Signer */
    uint8_t  lds_hash_alg;          /* SHA-256                     */
    uint8_t  dg_hashes[16][32];     /* hash per DG, indexed 1..16  */
    uint8_t  ds_signature[384];     /* RSA-PKCS1v15 or RSA-PSS     */
};

int passive_auth(const struct ef_sod *sod)
{
    /* (1) Chain DS cert to the country CSCA from ICAO PKD. */
    if (x509_chain_verify(sod->ds_cert, sod->ds_cert_len,
                          CSCA_PUB, CSCA_PUB_LEN))
        return PA_ERR_CHAIN;

    /* (2) Verify signed-data covering the DG hash list. */
    uint8_t h[32];
    sha256(sod->dg_hashes, sizeof sod->dg_hashes, h);
    if (verify_with_cert(sod->ds_cert, sod->ds_cert_len,
                         h, sod->ds_signature, 384))
        return PA_ERR_SIG;

    /* (3) Check DG1 (MRZ data) hash against sod->dg_hashes[1],
     * DG2 (facial image) against [2], DG3 (fingerprint) if
     * EAC-permitted, etc. */
    for (int i = 1; i <= 16; ++i) {
        uint8_t dg[32];
        if (!ef_dg_present(i)) continue;
        sha256_ef_dg(i, dg);
        if (memcmp(dg, sod->dg_hashes[i], 32))
            return PA_ERR_DG_HASH;
    }
    return PA_OK;
}

/* Active Authentication (AA): the chip proves it holds a
 * private key corresponding to the AA public key stored in
 * DG15 and committed to by EF.SOD. Border reader sends a
 * nonce; chip signs it. AA defeats chip cloning. */
int active_auth(const uint8_t *aa_pub, size_t aa_pub_len,
                const uint8_t *challenge, size_t ch_len,
                const uint8_t *chip_sig, size_t sig_len)
{
    uint8_t h[32]; sha256(challenge, ch_len, h);
    return rsa_pkcs1v15_verify_sha256(aa_pub, aa_pub_len,
                                       (uint8_t[]){1,0,1}, 3,
                                       h, 32, chip_sig, sig_len);
}

/* ---- Forgery surface once CSCA RSA is factored -----------
 *  * Forge DS cert under any CSCA -> sign arbitrary EF.SOD
 *    -> produce a chip with any identity (name, DOB, photo,
 *    fingerprint) that Passive Auth accepts at every border.
 *  * Active Auth still requires cloning the chip's private
 *    key; but if the AA key is also RSA and short (some
 *    countries use RSA-1024 for AA), it falls too.
 *  * Specific CSCA index 01 (RSA-2048) is the common case;
 *    some states have rotated to RSA-3072 or ECDSA.
 *
 *  Impact: unlimited identity fabrication for border crossing,
 *  terrorism watch-list evasion, sanctions evasion. "Perfect
 *  passport factory" with no physical insert required — just
 *  write to a blank JCOP chip.
 *
 *  Recovery: ICAO PKD rotation + every border's CSCA store
 *  updated + new passport issuance for every citizen. Multi-
 *  year, multi-hundred-billion-dollar global effort.
 * --------------------------------------------------------- */
