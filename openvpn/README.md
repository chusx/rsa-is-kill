# OpenVPN — RSA TLS Authentication

**Source:** https://github.com/OpenVPN/openvpn  
**File:** `src/openvpn/ssl_openssl.c`  
**License:** GPLv2

## what it does

OpenVPN uses RSA certificates for mutual TLS authentication between client and server. The code here implements a custom `RSA_METHOD` that hooks into OpenSSL's signing path, allowing OpenVPN to delegate private key operations to an external process (hardware token, management daemon).

## why is this hella bad

- RSA key exchange is used in the TLS handshake to authenticate peers. Once RSA is broken, any actor with a CRQC can impersonate any OpenVPN server or client.
- The `tls_ctx_use_management_external_key()` function dispatches on `EVP_PKEY_RSA` — there is no `EVP_PKEY_PQC` branch. The external key path is entirely RSA-specific.
- `rsa_priv_enc()` is called by OpenSSL during every TLS handshake to sign the CertificateVerify or ServerKeyExchange message. This is the exact operation Shor's algorithm attacks.
- OpenVPN has no native PQC support. Compiling against an OQS-patched OpenSSL is possible but unsupported and not done by any major distro package.

## migration status

no PQC roadmap published. most enterprise OpenVPN deployments use RSA-2048 certificates from internal CAs.
