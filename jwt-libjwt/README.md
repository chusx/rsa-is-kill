# jwt-libjwt — RS256 in OAuth2/OIDC everywhere

**Software:** libjwt (benmcollins/libjwt) — canonical C JWT library  
**Industry:** Web authentication, cloud APIs, microservices, enterprise SSO  
**Algorithm:** RSASSA-PKCS1-v1_5 (RS256/RS384/RS512) and RSASSA-PSS (PS256/PS384/PS512)  
**PQC migration plan:** None — no PQC algorithm registered in IANA JOSE registry (RFC 7518)

## What it does

JSON Web Tokens with RS256 are the default signing algorithm for:
- OAuth2 access tokens (RFC 9068)
- OpenID Connect ID tokens
- Kubernetes ServiceAccount tokens (default: RS256)
- AWS Cognito, Azure AD, Google Identity Platform
- Okta, Auth0, PingFederate
- Every API gateway that validates JWTs

RS256 means RSASSA-PKCS1-v1_5 with SHA-256 — broken by Shor's algorithm.
PS256 (RSA-PSS) is also RSA — also broken by Shor's algorithm.

The IANA JOSE Algorithms registry (RFC 7518) has no post-quantum entry.
NIST has not yet published a JOSE profile for ML-DSA or SLH-DSA.

## Why it's stuck

JWT is embedded in virtually every cloud-native application as the identity
token format. Changing the signing algorithm requires:
- New IANA JOSE algorithm identifiers for PQC
- Updated OIDC discovery documents (`jwks_uri`)
- Client library updates for every language
- Coordinated key rotation across all existing token issuers

Tokens with long expiry (common in service-to-service auth) may still be valid
when a CRQC appears. Any previously issued RS256 JWT can be forged by
recovering the private key from the public key in `jwks_uri`.

## Code

`jwt_openssl_sign_verify.c` — `openssl_sign_sha_pem()` showing RS256/RS384/RS512
all routing to `EVP_PKEY_RSA` with `EVP_DigestSign`, and PS256/PS384/PS512
to `EVP_PKEY_RSA_PSS` — every JWT signing algorithm is RSA.
