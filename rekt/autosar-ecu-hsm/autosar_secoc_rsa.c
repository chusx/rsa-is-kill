/*
 * Illustrative code based on AUTOSAR SecOC (Secure Onboard Communication)
 * and the EVITA (E-safety Vehicle Intrusion proTected Applications) HSM spec.
 *
 * Modern automotive ECUs (Electronic Control Units) use a Hardware Security
 * Module (HSM) — a dedicated crypto core integrated into the SoC
 * (e.g., Infineon AURIX TC3x, NXP S32G, Renesas RH850).
 *
 * AUTOSAR SecOC provides message authentication between ECUs on CAN/FlexRay/Eth.
 * EVITA defines HSM profiles (Full/Medium/Light) specifying allowed algorithms.
 *
 * RSA use in automotive:
 *   - ECU firmware signing: OEM signs ECU firmware with RSA-2048/3072
 *   - TLS for V2C (Vehicle-to-Cloud): RSA certificates for OTA update channels
 *   - AUTOSAR Crypto Stack: supports RSA through CsmPrimitives
 *   - Secure boot chain: SHE (Secure Hardware Extension) -> EVITA HSM
 *
 * Vehicle lifespan: 15-20 years. ECU firmware rarely receives crypto updates.
 * No PQC algorithm is defined in AUTOSAR R23-11 Crypto Stack or EVITA specs.
 */

#include <stdint.h>
#include <string.h>

/* AUTOSAR Crypto Stack — CsmSignature interface (AUTOSAR_SWS_CryptoServiceManager) */

/* Algorithm families available in AUTOSAR R23-11 CsmPrimitives (excerpt):
 *   CRYPTO_ALGOFAM_RSA           — RSA sign/verify/encrypt/decrypt
 *   CRYPTO_ALGOFAM_ECDSA         — ECDSA sign/verify
 *   CRYPTO_ALGOFAM_ED25519       — EdDSA (added in R22-11)
 *   CRYPTO_ALGOFAM_ML_DSA        — NOT DEFINED
 *   CRYPTO_ALGOFAM_SLH_DSA       — NOT DEFINED
 *   CRYPTO_ALGOFAM_ML_KEM        — NOT DEFINED
 */
#define CRYPTO_ALGOFAM_RSA    0x04u
#define CRYPTO_ALGOFAM_ECDSA  0x0Bu

/* ECU firmware update authentication (OEM → ECU over UDS 0x34/0x36/0x37)
 * The firmware image is signed by the OEM with RSA-2048 or RSA-3072.
 * The ECU HSM verifies the signature before flashing new firmware.
 * Key material is provisioned at ECU manufacture and stored in HSM OTP fuses.
 */
typedef struct {
    uint8_t  algorithm_id;      /* CRYPTO_ALGOFAM_RSA */
    uint16_t key_bits;          /* 2048 or 3072 */
    uint8_t  hash_algo;         /* SHA-256 = 0x04 */
    uint8_t  padding;           /* RSA_PKCS1_V15 = 0x01, RSA_PSS = 0x02 */
    uint8_t  public_key[384];   /* RSA modulus (max 3072 bits = 384 bytes) */
    uint32_t public_exponent;   /* 65537 */
} EVITA_RSA_PublicKey;

/*
 * UDS (ISO 14229) firmware authentication flow:
 * 1. Tester uploads signed firmware binary via UDS RequestDownload (0x34)
 * 2. ECU HSM verifies RSA-2048 signature over firmware hash
 * 3. Only on successful verify does ECU flash the new firmware
 *
 * The public key is stored in the ECU's HSM key storage at manufacture.
 * It cannot be updated through the same UDS channel (chicken-and-egg).
 * Replacing RSA keys requires a separate key provisioning session with
 * physical access (manufacturing line or dealer tool), which may not be
 * possible in the field.
 */
typedef Std_ReturnType (*Csm_SignatureVerifyFuncType)(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8 *dataPtr,       /* firmware image data */
    uint32 dataLength,
    const uint8 *signaturePtr,  /* RSA-2048 signature (256 bytes) */
    uint32 signatureLength,
    Crypto_VerifyResultType *verifyPtr
);

/* EVITA Full HSM profile — algorithm requirements (EVITA D3.3):
 *   Mandatory: AES-128, SHA-256, RSA-2048
 *   Optional:  ECDSA-P256, ECDH-P256
 *   PQC:       NOT SPECIFIED
 *
 * Infineon AURIX TC3x HSM (SHE+):
 *   - Implements: AES-128, SHA-256, RSA-2048, ECDSA-P256
 *   - PQC support: none
 *   - Field update: not possible (HSM firmware is ROM on AURIX TC3x)
 *
 * NXP S32G (HSE firmware):
 *   - Implements: AES, SHA, RSA-4096, ECDSA-P256/P384, EdDSA
 *   - PQC support: none in current HSE firmware releases
 *
 * Renesas RH850/P1x-C (SHE/ICUMHA):
 *   - RSA-2048 as optional extension, no PQC
 */

/* Vehicle fleet RSA key lifecycle problem:
 *
 * A 2025 model vehicle has:
 *   - 100-150 ECUs, each with its own RSA key for firmware authentication
 *   - TLS client certificate (RSA-2048) for V2C OTA update channel
 *   - These keys are burned at ECU manufacture, 6-18 months before vehicle sale
 *   - Vehicle sells in 2025, last ECU key expires in ~2040 (15yr lifespan)
 *
 * Regulatory mandate (UN R155/R156, ISO/SAE 21434):
 *   OEMs must maintain cybersecurity for the vehicle's operational lifetime.
 *   But the crypto hardware (HSM) cannot be physically replaced in the field.
 *
 * No automotive OEM has published a PQC migration roadmap for ECU HSMs.
 */
