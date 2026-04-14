/* Source: libreswan/libreswan
 *   programs/rsasigkey/rsasigkey.c
 *   lib/libswan/pubkey/pubkey_type_rsa.c
 *
 * Libreswan is the dominant open-source IKEv2/IPsec implementation for Linux.
 * It is used in enterprise VPNs, cloud VPN gateways, and government classified
 * network interconnects (STIGs require IPsec for classified traffic).
 *
 * IKEv2 (RFC 7296) uses RSA signatures for peer authentication:
 *   - IKE_AUTH exchange: both ends sign the AUTH payload with RSA private key
 *   - Certificate-based authentication: RSA-2048 or RSA-3072 X.509 certs
 *   - Raw RSA keys (ipsec.secrets): RSA-2048 to RSA-4096 via rsasigkey tool
 *
 * Default rsasigkey key size: random between 3072 and 4096 bits (MIN_KEYBIT=2192).
 * Despite strong defaults, the IKEv2 protocol has no PQC authentication defined.
 * RFC 8784 (PQC for IKEv2) only adds post-quantum KEM via PPK — not auth.
 * Authentication (who you are) remains RSA or ECDSA in all IKEv2 implementations.
 */

/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 1999-2020 various authors */

#include <openssl/rsa.h>
#include <pk11pub.h>   /* NSS (Network Security Services) */

/* Minimum and default RSA key sizes for IKEv2 raw RSA keys.
 * libreswan intentionally avoids monoculture by randomizing key size. */
#define MIN_KEYBIT    2192   /* absolute minimum (NIST deprecated RSA-2048) */
#define F4            65537  /* public exponent, FIPS 186-4 compliant */

/*
 * RSA_pubkey_content_to_ipseckey() — serialize an RSA public key to DNS IPSECKEY format.
 * RFC 3110 defines the DNS IPSECKEY format for RSA public keys used in IKEv2.
 * The modulus and exponent are published in DNS for opportunistic IPsec (OE).
 *
 * Publishing the RSA modulus in DNS is the IKEv2 analog of the key escrow
 * problem: the public key is globally accessible, so a CRQC can factor it
 * to recover the private key and decrypt or impersonate any VPN peer.
 */
static err_t RSA_pubkey_content_to_ipseckey(const struct pubkey_content *pkc,
                                             chunk_t *ipseckey,
                                             enum ipseckey_algorithm_type *algo)
{
    SECKEYRSAPublicKey *rsa = &pkc->public_key->u.rsa;
    chunk_t exponent = same_secitem_as_chunk(rsa->publicExponent);  /* e */
    chunk_t modulus  = same_secitem_as_chunk(rsa->modulus);          /* n */

    /* Pack as RFC 3110: [1-byte exponent_len][exponent][modulus]
     * or [3-byte exponent_len][exponent][modulus] if exponent > 255 bytes */
    size_t rrlen = exponent.len + modulus.len + 3;
    uint8_t *buf = alloc_bytes(rrlen, "rfc3110");
    uint8_t *p = buf;

    if (exponent.len <= 255) {
        *p++ = exponent.len;
    } else {
        *p++ = 0;
        *p++ = (exponent.len >> 8) & 0xff;
        *p++ = exponent.len & 0xff;
    }
    memcpy(p, exponent.ptr, exponent.len); p += exponent.len;
    memcpy(p, modulus.ptr, modulus.len);   p += modulus.len;

    *ipseckey = (chunk_t){ buf, p - buf };
    *algo = IPSECKEY_ALGORITHM_RSA;   /* RFC 4025 algorithm type 1 = RSA */
    return NULL;
}

/*
 * IKEv2 AUTH payload signing (IKE_AUTH exchange):
 * Both IPsec peers sign:
 *   AUTH = prf(SK_px, <IKE_INIT_msg> || Ni || prf(SK_px, ID))
 * with their RSA private key (PKCS#1 v1.5 or RSASSA-PSS per RFC 7427).
 *
 * RFC 7427 (Signature Authentication in IKEv2) defines:
 *   - RSASSA-PSS with SHA-2 (algorithm ID 9)
 *   - RSASSA-PKCS1-v1_5 with SHA-1, SHA-256, SHA-384, SHA-512
 *   - ECDSA with SHA-256, SHA-384, SHA-512
 *   - No PQC algorithm IDs are defined
 *
 * RFC 8784 (Mixing Preshared Keys in IKEv2) addresses PQC KEM but NOT auth:
 *   "This document does not provide post-quantum security for the IKE SA
 *    authentication." — RFC 8784 §1
 *
 * Government classified networks (NSA/CNSS IANA 1253B):
 *   Suite B requires ECDH + ECDSA for IPsec. Suite B is deprecated, replaced
 *   by "Commercial National Security Algorithm Suite 2.0" (CNSA 2.0) which
 *   mandates PQC — but IKEv2 has no standard way to negotiate PQC auth yet.
 */
