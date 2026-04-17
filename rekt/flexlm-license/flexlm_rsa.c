/*
 * flexlm_rsa.c
 *
 * FlexLM / FlexNet Publisher — RSA license signing for commercial software.
 * Repository: Flexera Software (proprietary, not public)
 * Source: Reverse engineering of FlexNet lmgrd/lmutil; published security research
 *         by Bart Blaze, Jonathan Afek; academic work on FlexLM license cracking.
 *
 * FlexLM (now FlexNet Publisher) is the dominant software license management system
 * for commercial and scientific software. It is used by virtually every major EDA,
 * simulation, CAD, and scientific computing vendor:
 *
 *   EDA (Electronic Design Automation):
 *     - Synopsys Design Compiler, Primetime, VCS, Verdi — ~$1B annual FlexLM revenue
 *     - Cadence Virtuoso, Spectre, Innovus — Intel, TSMC, Samsung fabs
 *     - Mentor (Siemens EDA) Calibre, Xcelium — IC physical verification
 *     - Ansys HFSS, Maxwell, Mechanical — chip package and system simulation
 *
 *   Scientific/Engineering:
 *     - MATLAB + toolboxes (MathWorks) — universities, DoD, aerospace, medical
 *     - Simulink — automotive model-based design (every major OEM)
 *     - COMSOL Multiphysics — FEM simulation in nuclear, aerospace, biomedical
 *     - Abaqus (SIMULIA) — structural analysis in aerospace and automotive
 *
 *   Other:
 *     - Autodesk Civil 3D, Plant 3D — engineering infrastructure design
 *     - Dassault CATIA / ENOVIA — aerospace (Airbus, Boeing structural design)
 *     - MSC Nastran, Adams — vehicle dynamics simulation
 *
 * FlexLM uses RSA-1024 (legacy) or RSA-2048 to sign license files.
 * The vendor's RSA public key is embedded in the licensed application binary.
 * The license file contains: feature names, expiry dates, seat counts, hostid,
 * and an RSA signature (SIGN= field in the license text file).
 *
 * An attacker who derives the vendor's RSA private key can:
 *   - Generate valid, unexpired licenses for any Synopsys/Cadence/MATLAB feature
 *   - Bypass all seat count limits (infinite concurrent users)
 *   - Forge licenses for features not purchased
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

/*
 * FlexLM license file format (simplified):
 *
 * SERVER this_host HOSTNAME 27000
 * VENDOR synopsys
 * USE_SERVER
 * FEATURE dc_syn synopsys 2024.1 01-jan-2025 1 SIGN="3A4F 2B1C ... (RSA-1024 or RSA-2048)"
 * FEATURE vcs_mx synopsys 2024.1 01-jan-2025 unlimited SIGN="..."
 *
 * The SIGN= field is the RSA signature over the license feature data.
 * FlexLM uses a non-standard RSA signing scheme: the signature is encoded
 * as space-separated hex groups and uses a "FLEXlm obfuscation" of the
 * message before RSA signing. The public key is compiled into the vendor daemon
 * (synopsys_lmgrd, mlm for MATLAB, etc.).
 */

/*
 * flexlm_parse_sign_field() — parse the SIGN= hex field from a FlexLM license.
 *
 * FlexLM stores RSA signatures as a hex string with spaces every 4 characters.
 * Example: SIGN="3A4F 2B1C 9E07 ... FF3D"
 * This decodes to a 128-byte (RSA-1024) or 256-byte (RSA-2048) signature.
 */
int
flexlm_parse_sign_field(const char *sign_str,
                         uint8_t *sig_out, size_t *sig_len_out)
{
    const char *p = sign_str;
    size_t len = 0;

    while (*p && len < 256) {
        /* skip spaces */
        while (*p == ' ') p++;
        if (!*p || *p == '"') break;

        /* read 4 hex chars */
        unsigned int byte_hi, byte_lo;
        if (sscanf(p, "%02x%02x", &byte_hi, &byte_lo) != 2) return -1;
        sig_out[len++] = (uint8_t)byte_hi;
        sig_out[len++] = (uint8_t)byte_lo;
        p += 4;
    }
    *sig_len_out = len;
    return 0;
}

/*
 * flexlm_verify_license_feature() — verify RSA signature on a license feature line.
 *
 * This is (a simplified model of) what the vendor daemon does when the FlexLM
 * license manager checks whether a license checkout is valid.
 *
 * The vendor RSA public key (n, e) is compiled into the vendor daemon binary.
 * For Synopsys: RSA-1024 in older platforms, RSA-2048 in newer.
 * For MathWorks (MATLAB): RSA-1024 historically, RSA-2048 current.
 * For Cadence: RSA-2048.
 *
 * An attacker who has the vendor RSA private key can call this with any feature
 * name, any expiry date, any seat count, and the signature will verify.
 * The vendor private key is derivable from the vendor public key (in the daemon binary)
 * given a CRQC. The daemon binary is available to anyone who has the software installed.
 */
int
flexlm_verify_license_feature(const char *feature_name,
                                const char *version_str,
                                const char *expiry_str,
                                int seat_count,
                                const uint8_t *signature, size_t sig_len,
                                RSA *vendor_pubkey)
{
    char message[512];
    uint8_t digest[20];  /* FlexLM legacy uses SHA-1 internally */
    uint8_t decrypted[256];
    int decrypted_len;
    int ret;

    /*
     * Construct the message to be verified.
     * FlexLM uses a specific normalization of the feature fields.
     * (Actual FlexLM message construction is more complex and obfuscated,
     * but the core operation is: hash the normalized fields, RSA verify.)
     */
    snprintf(message, sizeof(message), "%s:%s:%s:%d",
             feature_name, version_str, expiry_str, seat_count);

    /* SHA-1 of the normalized message (legacy FlexLM uses SHA-1) */
    SHA1((uint8_t *)message, strlen(message), digest);

    /*
     * RSA public key operation: m = sig^e mod n
     * This is RSA_public_decrypt with RSA_NO_PADDING.
     * FlexLM applies its own padding scheme after the raw RSA operation.
     */
    decrypted_len = RSA_public_decrypt(sig_len, signature, decrypted,
                                        vendor_pubkey, RSA_NO_PADDING);
    if (decrypted_len < 0) return -1;

    /*
     * Verify the decrypted value contains the SHA-1 digest.
     * (Simplified — real FlexLM uses a custom obfuscation here.)
     */
    ret = memcmp(decrypted + decrypted_len - 20, digest, 20);
    return (ret == 0) ? 1 : 0;
}

/*
 * flexlm_forge_license_feature() — generate a valid RSA signature for any license.
 *
 * This requires the vendor RSA PRIVATE key — not publicly available normally.
 * But with a CRQC and the vendor RSA PUBLIC key (from the daemon binary), the
 * private key is derivable.
 *
 * Once you have the private key, you can sign any license feature with any
 * parameters: feature name, version, expiry date, seat count.
 *
 * "unlimited" seat count, expiry date "01-jan-2099", all features.
 * This is what every FlexLM license cracker has been trying to do for 30 years.
 * Quantum computing does it mathematically.
 */
int
flexlm_forge_license_feature(const char *feature_name,
                               const char *version_str,
                               const char *expiry_str,
                               int seat_count,
                               RSA *vendor_privkey,
                               uint8_t *signature_out, size_t *sig_len_out)
{
    char message[512];
    uint8_t digest[20];
    int ret;

    snprintf(message, sizeof(message), "%s:%s:%s:%d",
             feature_name, version_str, expiry_str, seat_count);
    SHA1((uint8_t *)message, strlen(message), digest);

    *sig_len_out = RSA_size(vendor_privkey);

    /* RSA private key operation: sig = digest^d mod n */
    ret = RSA_private_encrypt(20, digest, signature_out,
                               vendor_privkey, RSA_NO_PADDING);
    return (ret > 0) ? 0 : -1;
}
