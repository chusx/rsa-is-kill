/* Source: aws/aws-iot-device-sdk-embedded-C
 *         + aws/amazon-freertos (coreMQTT-Agent)
 *
 * AWS IoT Core uses X.509 mutual TLS authentication for every device connection.
 * By default, the AWS IoT Console generates RSA-2048 device certificates.
 * ~1 billion devices connect to AWS IoT Core globally (2024 AWS estimate).
 *
 * The same pattern applies to:
 *   - Azure IoT Hub (X.509 RSA-2048 device certs, DPS provisioning)
 *   - Google Cloud IoT Core (deprecated 2023, now Pub/Sub — still RSA)
 *   - Tuya, Alexa, Matter/Thread — all use RSA or ECDSA device certs
 *
 * IoT device lifespan: 5-15 years depending on category.
 * Microcontrollers (ESP32, STM32, nRF52): no key agility, cert in flash.
 * No PQC device certificate profile is supported by AWS IoT Core, Azure IoT,
 * or the Matter 1.x specification.
 */

/* Typical AWS IoT device certificate (RSA-2048, self-signed or by custom CA):
 *
 * Certificate:
 *     Data:
 *         Version: 3 (0x2)
 *         Serial Number: 0x0f3a...
 *         Signature Algorithm: sha256WithRSAEncryption   ← RSA
 *         Issuer: CN=my-iot-ca
 *         Validity: Not Before: Apr 14 2025, Not After: Apr 14 2035  ← 10yr
 *         Subject: CN=device-00:11:22:33:44:55
 *         Subject Public Key Info:
 *             Public Key Algorithm: rsaEncryption        ← RSA-2048
 *             RSA Public Key: (2048 bit)
 *         X509v3 extensions:
 *             X509v3 Extended Key Usage: TLS Web Client Authentication
 */

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* AWS IoT Provisioning by Claim — device bootstraps with a shared RSA cert,
 * then exchanges it for a unique device certificate via the Fleet Provisioning API. */

typedef struct {
    const char *cert_pem;       /* PEM: RSA-2048 X.509 device certificate */
    const char *privkey_pem;    /* PEM: RSA-2048 private key (stored in flash) */
    const char *root_ca_pem;    /* PEM: Amazon Root CA 1 (RSA-2048) */
} AWSIoTCredentials;

/*
 * FreeRTOS corePKCS11 — PKCS#11 shim for embedded TLS.
 * Device private key stored in flash via PKCS#11 PAL (Platform Abstraction Layer).
 * Key type: CKK_RSA (2048-bit) or CKK_EC (P-256) depending on provisioning.
 * AWS IoT console default: RSA-2048.
 *
 * From AWS IoT documentation (2024):
 * "We recommend using RSA 2048-bit keys or EC keys with the P-256 curve."
 * No mention of PQC. AWS IoT Certificate Manager does not support PQC algorithms.
 */

/* ESP-IDF (Espressif ESP32) — mbedTLS for MQTT/TLS to AWS IoT.
 * RSA-2048 private key stored in NVS (Non-Volatile Storage) partition.
 * Key generation at provisioning (factory or first boot).
 *
 * From esp-aws-iot/examples/mqtt/tls_mutual_auth/main/tls_mutual_auth.c:
 *   mbedtls_pk_init(&priv_key);
 *   mbedtls_pk_parse_key(&priv_key, (const unsigned char *)privkey_pem, ...);
 *   mbedtls_ssl_conf_own_cert(&ssl_conf, &device_cert, &priv_key);
 *
 * The private key is RSA-2048 PEM stored in flash at offset 0x310000.
 * On ESP32, there is no TEE or hardware key storage — it is in plaintext NVS.
 * On ESP32-S3 with eFuse-encrypted flash: key is encrypted at rest with AES,
 * but the RSA key material is still RSA. A CRQC breaks the cert, not the AES.
 */

/* Nordic nRF9160 (LTE IoT modem with TLS offload):
 * The modem has an internal TLS stack. RSA certificates provisioned via AT commands:
 *   AT%CMNG=0,0,0,"<CA_cert_PEM>"
 *   AT%CMNG=0,0,1,"<client_cert_PEM>"
 *   AT%CMNG=0,0,2,"<private_key_PEM>"
 * Once stored in modem flash, keys cannot be changed without modem AT access.
 * nRF9160 modem firmware does not support PQC algorithms.
 */

/* Matter (formerly CHIP) — IoT device commissioning.
 * Matter uses ECDSA P-256 for device attestation (Device Attestation Credential).
 * The DAC is provisioned at manufacture by a PAA-certified factory.
 * PAA (Product Attestation Authority) root cert: ECDSA P-256.
 * No PQC support in Matter 1.0, 1.1, 1.2, or 1.3 specifications.
 * Google, Apple, Amazon all operate Matter PAAs — all using ECDSA P-256.
 */

/* Lifespan analysis:
 *   Industrial IoT sensor (factory floor): 10-15 years
 *   Smart home device (thermostat, lock): 7-10 years
 *   LTE-M/NB-IoT tracker (asset tracking): 5-10 years
 *   Agricultural IoT (soil sensors): 5-15 years
 *
 * All of these devices provision an RSA-2048 or ECDSA-P256 certificate
 * at manufacture. There is no remote re-keying protocol defined in
 * AWS IoT Core, Azure DPS, or Matter that would replace the leaf certificate
 * without physical access or a full firmware reflash.
 */
