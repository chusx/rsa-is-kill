/*
 * siemens_s7_rsa.c
 *
 * Siemens TIA Portal / S7comm-plus — RSA session authentication for S7-1200/1500 PLCs.
 * This is the crypto layer that Stuxnet had to work around by stealing code signing certs.
 *
 * Source: S7comm-plus protocol dissector research; Siemens security advisories;
 *         wireshark-plugins-s7comm (https://github.com/wireshark/wireshark S7comm dissector);
 *         published academic analysis of S7comm-plus by Klick, Rademacher et al. (2015)
 *
 * S7comm-plus is the successor protocol to S7comm, introduced with S7-1200/1500 PLCs.
 * It uses RSA-2048 for session key establishment. The PLC has a device certificate
 * signed by the Siemens Device CA (a private Siemens PKI, not publicly trusted).
 *
 * Siemens deployments in critical infrastructure:
 *   - BASF, Bayer, SABIC — chemical plant process control
 *   - Volkswagen, Mercedes, BMW — automotive manufacturing
 *   - Deutsche Bahn — railway signaling and infrastructure
 *   - Thyssen Krupp Steel — blast furnace and rolling mill control
 *   - Iran Natanz uranium enrichment facility (historical) — the Stuxnet target
 *   - Nuclear power plants worldwide (IEC 62645 scope)
 *
 * The S7-1500 PLC generates an RSA-2048 keypair during commissioning.
 * TIA Portal generates an RSA-2048 project certificate for PLC program authentication.
 * The public keys are transmitted in TLS handshakes; the private keys are in the PLC hardware.
 *
 * S7comm-plus session establishment (simplified):
 *   Client (TIA Portal/SCADA) -> PLC: ClientHello (S7comm-plus header)
 *   PLC -> Client: ServerHello + RSA-2048 device certificate
 *   Client: verify cert chain against Siemens Device CA
 *   Client -> PLC: RSA-OAEP encrypted session key material
 *   PLC: decrypt with RSA private key, derive session keys
 *   Session: AES-128 encrypted S7comm-plus PDUs
 *
 * An attacker who factors the PLC's RSA-2048 certificate (available from any
 * S7comm-plus handshake on the OT network) can:
 *   - Impersonate the PLC to any engineering workstation
 *   - Decrypt any recorded S7comm-plus session traffic
 *   - Forge PLC program authentication, load modified programs
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/*
 * S7comm-plus protocol constants
 */
#define S7COMMP_OPCODE_REQ          0x31
#define S7COMMP_OPCODE_RES          0x32
#define S7COMMP_FUNC_CREATEOBJ      0x04
#define S7COMMP_FUNC_SETMULTIVAR    0x04CA

/* S7-1500 device certificate — RSA-2048, signed by Siemens Device CA */
/* Available in plaintext from any S7comm-plus TCP session on port 102 */
#define S7_DEVICE_CERT_DER_LEN      1024  /* ~1KB DER encoded RSA-2048 cert */

/*
 * s7commp_session_init() — parse S7comm-plus session setup, extract PLC cert.
 *
 * Called by TIA Portal / WinCC / STEP 7 when connecting to an S7-1200/1500 PLC.
 * The PLC sends its RSA-2048 device certificate during session setup.
 * This certificate is transmitted in cleartext before any encryption is established.
 */
int
s7commp_session_init(const uint8_t *pdu, size_t pdu_len,
                     X509 **plc_cert_out)
{
    const uint8_t *p;
    X509 *plc_cert;
    uint16_t cert_len;

    /*
     * S7comm-plus session PDU structure (simplified):
     *   [0..1]  Protocol ID (0x72 0xF1)
     *   [2]     Opcode (0x32 = Response, 0x31 = Request)
     *   [3..4]  Data length
     *   [5..6]  Sequence number
     *   [7..]   Session setup TLV data
     *
     * Within the session setup TLVs, the PLC certificate is at attribute 0x09EF:
     *   Attr ID: 0x09EF (device certificate)
     *   Attr type: 0x1D (byte array)
     *   Length: 2 bytes
     *   Data: DER-encoded X.509 RSA-2048 certificate
     */
    p = pdu + 7;  /* skip S7comm-plus header */

    /* Find certificate attribute 0x09EF in TLV stream */
    while (p < pdu + pdu_len - 4) {
        uint32_t attr_id = (p[0] << 8) | p[1];
        uint8_t  attr_type = p[2];
        if (attr_id == 0x09EF && attr_type == 0x1D) {
            cert_len = (p[3] << 8) | p[4];
            p += 5;
            /* DER decode the PLC's RSA-2048 certificate */
            plc_cert = d2i_X509(NULL, &p, cert_len);
            if (!plc_cert) return -1;
            *plc_cert_out = plc_cert;
            return 0;
        }
        p += 3 + ((p[3] << 8) | p[4]) + 2;  /* skip this TLV */
    }
    return -1;
}

/*
 * s7commp_encrypt_session_key() — RSA-OAEP encrypt session key for PLC.
 *
 * Called by TIA Portal after receiving and verifying the PLC's RSA-2048 certificate.
 * The session key (AES-128) is encrypted with the PLC's RSA public key.
 * The PLC decrypts it with its private key to establish the encrypted channel.
 *
 * An attacker who factors the RSA-2048 key recovers the session key and decrypts
 * all subsequent AES-encrypted S7comm-plus traffic — including ladder logic reads,
 * process variable values, and PLC program uploads.
 */
int
s7commp_encrypt_session_key(X509 *plc_cert,
                             const uint8_t *session_key, size_t key_len,
                             uint8_t *encrypted_key_out, size_t *encrypted_key_len)
{
    EVP_PKEY *plc_pubkey;
    EVP_PKEY_CTX *ctx;
    int ret = -1;

    /* Extract RSA-2048 public key from PLC certificate */
    plc_pubkey = X509_get_pubkey(plc_cert);
    if (!plc_pubkey) return -1;

    ctx = EVP_PKEY_CTX_new(plc_pubkey, NULL);
    if (!ctx) goto out;

    /* RSA-OAEP encrypt — session key goes to PLC */
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto out;

    *encrypted_key_len = 256;  /* RSA-2048 output is always 256 bytes */
    if (EVP_PKEY_encrypt(ctx, encrypted_key_out, encrypted_key_len,
                          session_key, key_len) <= 0) goto out;

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(plc_pubkey);
    return ret;
}

/*
 * tia_verify_project_signature() — verify RSA signature on TIA Portal project file.
 *
 * TIA Portal (.ap17/.ap18) project files contain PLC programs (ladder logic, FBD, SCL).
 * Siemens signs project files with an RSA-2048 "project certificate" to prevent
 * unauthorized program modifications. The PLC checks this signature before accepting
 * a program download.
 *
 * The project certificate public key is embedded in the project file and transmitted
 * to the PLC. An attacker who can forge this RSA signature can load arbitrary PLC
 * programs — exactly the Stuxnet attack objective, achieved there via stolen certs.
 */
int
tia_verify_project_signature(const uint8_t *project_data, size_t data_len,
                               const uint8_t *signature, size_t sig_len,
                               X509 *project_cert)
{
    EVP_PKEY *project_key;
    EVP_MD_CTX *md_ctx;
    int ret;

    project_key = X509_get_pubkey(project_cert);
    if (!project_key) return -1;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) { EVP_PKEY_free(project_key); return -1; }

    /* RSA-SHA256 PKCS#1 v1.5 signature verification */
    /* project_cert is RSA-2048; its public key is in the project file */
    ret = EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, project_key);
    if (ret <= 0) goto out;

    ret = EVP_DigestVerifyUpdate(md_ctx, project_data, data_len);
    if (ret <= 0) goto out;

    ret = EVP_DigestVerifyFinal(md_ctx, signature, sig_len);
    /* ret == 1: valid signature, PLC accepts the program download */
    /* ret == 0: invalid signature, PLC rejects — unless you forged it */

out:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(project_key);
    return ret;
}

/*
 * Stuxnet context:
 *
 * Stuxnet (2010) targeted Siemens S7-315 and S7-417 PLCs controlling Iranian
 * centrifuges at Natanz. It used FOUR zero-days, including stolen Authenticode
 * code signing certificates (Realtek Semiconductor, JMicron Technology) to sign
 * its Windows drivers as legitimate software.
 *
 * The S7-315/417 used S7comm (not S7comm-plus) — no RSA authentication at the
 * PLC protocol level. Stuxnet could write directly to the PLC over S7comm.
 *
 * The S7-1200/1500 series (released 2010-2013) added S7comm-plus with RSA-2048
 * session authentication specifically as a response to Stuxnet-style attacks.
 *
 * A CRQC that can factor RSA-2048 would:
 *   1. Break S7comm-plus session authentication — impersonate any PLC
 *   2. Decrypt recorded S7comm-plus sessions — recover process values and programs
 *   3. Forge TIA Portal project certificates — load arbitrary PLC programs
 *
 * This is exactly Stuxnet, but without needing stolen certificates.
 */
