/*
 * quote_v4_layout.h
 *
 * Intel DCAP v4 TDX Quote binary layout (for TDX 1.5 and later).
 * Matches `struct sgx_quote4` in `sgx-dcap-quote-verification` but with
 * TD-specific body (MRTD, RTMR0..3) rather than SGX enclave measurements.
 */

#ifndef TDX_QUOTE_V4_LAYOUT_H
#define TDX_QUOTE_V4_LAYOUT_H

#include <stdint.h>

#define TDX_QUOTE_VERSION_4        4
#define TDX_ATTESTATION_KEY_TYPE_ECDSA_P256   2
#define TDX_TEE_TYPE_TDX           0x00000081

#define TDX_MRTD_BYTES             48     /* SHA-384 */
#define TDX_RTMR_BYTES             48
#define TDX_RTMR_COUNT             4
#define TDX_REPORT_DATA_BYTES      64
#define TDX_QE_ECDSA_SIG_BYTES     64
#define TDX_QE_ECDSA_PUBKEY_BYTES  64

/* TDX Report Body (`td_info_t`) — what the TD actually measures itself as. */
struct tdx_td_report_body {
    uint8_t  tee_tcb_svn[16];        /* TDX Module SVN */
    uint8_t  mrseam[48];             /* SEAM module hash */
    uint8_t  mrsignerseam[48];       /* Intel signer of SEAM */
    uint64_t seam_attributes;
    uint64_t td_attributes;          /* TUD / SEPT_VE_DISABLE / DEBUG / etc. */
    uint64_t xfam;                   /* XCR0-like features */

    uint8_t  mrtd[TDX_MRTD_BYTES];   /* TD build-time measurement */
    uint8_t  mrconfigid[48];         /* VM configuration ID */
    uint8_t  mrowner[48];
    uint8_t  mrownerconfig[48];

    uint8_t  rtmr[TDX_RTMR_COUNT][TDX_RTMR_BYTES];  /* runtime measurements */
    uint8_t  report_data[TDX_REPORT_DATA_BYTES];    /* caller-supplied (nonce, etc.) */
};

struct tdx_quote_header {
    uint16_t version;                 /* 4 */
    uint16_t att_key_type;            /* ECDSA-P256 over TD report body */
    uint32_t tee_type;                /* 0x81 = TDX */
    uint16_t qe_svn;
    uint16_t pce_svn;
    uint8_t  qe_vendor_id[16];        /* Intel's QE vendor ID */
    uint8_t  user_data[20];
};

struct tdx_quote_v4 {
    struct tdx_quote_header      header;
    struct tdx_td_report_body    td_report;

    /* Signature section */
    uint32_t sig_data_len;
    uint8_t  ecdsa_signature[TDX_QE_ECDSA_SIG_BYTES];   /* over header+td_report */
    uint8_t  ecdsa_attestation_pubkey[TDX_QE_ECDSA_PUBKEY_BYTES];

    /* QE report + its signature (by the PCK leaf cert) */
    uint8_t  qe_report[384];
    uint8_t  qe_report_signature[64];

    /* Cert chain: PCK leaf (ECDSA on prime256v1 curve, signed by Intel
     * Processor CA RSA-3072) || Processor CA (RSA-3072, signed by Root
     * CA RSA-3072) || Root CA (RSA-3072, self-signed).
     *
     * The PCK certs are X.509 with Intel's SGX/TDX extensions carrying
     * TCB component SVNs. The CA chain is RSA. Root CA pubkey must match
     * Intel's hardcoded pubkey. */
    uint32_t cert_data_type;          /* 5 = PCK cert chain */
    uint32_t cert_data_len;
    uint8_t  cert_chain_pem[0];       /* flexible */
};

/* Intel SGX/TDX Root CA public key (RSA-3072) — hardcoded in every DCAP
 * verifier. Published at
 * https://api.trustedservices.intel.com/sgx/certification/v4/rootcacrl
 * and embedded in `sgx_dcap_quoteverify_sample` and friends. */
extern const uint8_t INTEL_SGX_ROOT_CA_MODULUS[384];
extern const uint8_t INTEL_SGX_ROOT_CA_EXPONENT[3];

#endif
