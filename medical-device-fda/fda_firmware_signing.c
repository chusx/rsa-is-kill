/*
 * Illustrative code based on FDA guidance "Cybersecurity in Medical Devices"
 * (2023), IEC 62443-4-2, and UL 2900-2-1.
 *
 * FDA 21 CFR Part 820 and the 2023 Consolidated Appropriations Act (Section 3305)
 * require medical device manufacturers to:
 *   - Provide a Software Bill of Materials (SBOM)
 *   - Implement cryptographically authenticated firmware updates
 *   - Have a coordinated vulnerability disclosure process
 *
 * FDA-cleared medical devices using RSA/ECDSA for firmware authentication:
 *   - Insulin pumps and closed-loop AID (Automated Insulin Delivery) systems
 *   - Implantable cardiac devices (pacemakers, ICDs, CRT-D)
 *   - Infusion pumps (hospital IV, PCA pumps)
 *   - Patient monitors (vital signs, bedside monitors)
 *   - Diagnostic imaging (CT, MRI, X-ray — Windows-based, use Authenticode RSA)
 *   - Surgical robots (da Vinci — update server TLS uses RSA)
 *   - Ventilators and CPAP machines (post-COVID FDA EUA updates)
 *
 * No PQC algorithm is required or referenced in any FDA guidance document.
 * IEC 62443 and UL 2900 security standards do not specify PQC.
 * Medical device lifespan: 10-15 years for implants, 5-10 years for connected devices.
 */

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>

/* Generic medical device firmware update authentication:
 * OEM signs firmware image with RSA-2048 private key (held in secure build HSM).
 * Device verifies signature before applying update.
 * Public key baked into device bootloader / secure element at manufacture.
 */

#define FW_SIG_ALGO_RSA2048_SHA256  0x01
#define FW_HEADER_MAGIC             0x4D454446  /* "MEDF" */

typedef struct __attribute__((packed)) {
    uint32_t magic;             /* FW_HEADER_MAGIC */
    uint32_t firmware_length;
    uint8_t  version[4];        /* major.minor.patch.build */
    uint8_t  sha256_hash[32];   /* SHA-256 of firmware payload */
    uint8_t  sig_algo;          /* FW_SIG_ALGO_RSA2048_SHA256 */
    uint8_t  signature[256];    /* RSA-2048 PKCS#1 v1.5 signature */
} FirmwareHeader;

/* Verify a medical device firmware image before applying the update.
 * Called by the bootloader or secure element before flash write.
 *
 * @header:     Firmware header containing signature
 * @payload:    Firmware binary data
 * @oem_pubkey: RSA-2048 public key baked into device at manufacture
 */
int medical_device_verify_firmware(const FirmwareHeader *header,
                                    const uint8_t *payload,
                                    RSA *oem_pubkey)
{
    uint8_t computed_hash[SHA256_DIGEST_LENGTH];
    int ret;

    /* Verify firmware payload hash matches header */
    SHA256(payload, header->firmware_length, computed_hash);
    if (memcmp(computed_hash, header->sha256_hash, SHA256_DIGEST_LENGTH) != 0)
        return -1;   /* integrity failure */

    /* RSA-2048 PKCS#1 v1.5 signature verification */
    ret = RSA_verify(NID_sha256,
                     header->sha256_hash, SHA256_DIGEST_LENGTH,
                     header->signature, sizeof(header->signature),
                     oem_pubkey);
    return (ret == 1) ? 0 : -1;
}

/*
 * Implantable device considerations:
 *
 * Cardiac implantable electronic devices (CIEDs — pacemakers, ICDs):
 *   - Programmed via proprietary RF (Medtronic: 175 kHz, Abbott: MICS band)
 *   - Firmware updates transmitted OTA via programmer wand (physical proximity)
 *   - OR via remote monitoring (Medtronic CareLink, Abbott Merlin.net)
 *   - RSA/ECDSA used to authenticate update packages from the cloud
 *
 * Insulin pumps (closed-loop AID systems):
 *   - Tandem t:slim X2: firmware update via USB or Bluetooth
 *   - Medtronic MiniMed 780G: OTA via Bluetooth + mobile app
 *   - Insulet OmniPod 5: OTA via Bluetooth
 *   - All use RSA or ECDSA to sign firmware packages
 *   - Cloud connection uses TLS with RSA certificates
 *
 * Vulnerability: if the OEM code-signing private key is recovered via CRQC,
 * an attacker can craft a malicious firmware update. For AID systems,
 * this could manipulate insulin delivery. For ICDs, could disable therapy.
 * FDA has issued guidance on firmware security but mandates no specific algorithms.
 *
 * "Substantial equivalence" (510(k)) clearance process: changing the
 * cryptographic algorithm in an already-cleared device may require a new
 * 510(k) submission or De Novo request, adding 6-18 months of regulatory delay.
 *
 * Post-market migration is therefore both technically and regulatorily expensive.
 */
