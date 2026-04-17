# jwt-libjwt — RS256 in OAuth2/OIDC everywhere

**Software:** libjwt (benmcollins/libjwt) — canonical C JWT library 
**Industry:** Web authentication, cloud APIs, microservices, enterprise SSO 
**Algorithm:** RSASSA-PKCS1-v1_5 (RS256/RS384/RS512) and RSASSA-PSS (PS256/PS384/PS512) 

## What it does

JSON Web Tokens with RS256 are the default signing algorithm for:
- OAuth2 access tokens (RFC 9068)
- OpenID Connect ID tokens
- Kubernetes ServiceAccount tokens (default: RS256)
- AWS Cognito, Azure AD, Google Identity Platform
- Okta, Auth0, PingFederate
- Every API gateway that validates JWTs

RS256 means RSASSA-PKCS1-v1_5 with SHA-256 — broken by the factoring algorithm.
PS256 (RSA-PSS) is also RSA — also broken by the factoring algorithm.

The IANA JOSE Algorithms registry (RFC 7518) has no non-RSA entry.
NIST has not yet published a JOSE profile for ML-DSA or SLH-DSA.

## Why it's stuck

JWT is embedded in virtually every cloud-native application as the identity
token format. Changing the signing algorithm requires:
- New IANA JOSE algorithm identifiers for non-RSA
- Updated OIDC discovery documents (`jwks_uri`)
- Client library updates for every language
- Coordinated key rotation across all existing token issuers

Tokens with long expiry (common in service-to-service auth) may still be valid
when a factoring break appears. Any previously issued RS256 JWT can be forged by
recovering the private key from the public key in `jwks_uri`.

## impact

RS256 is the signing algorithm for OAuth2 access tokens, OIDC ID tokens, and Kubernetes ServiceAccount tokens. the public key is published at the jwks_uri endpoint, openly, by design, for all to see. input for the attack served on a silver platter.

- forge any user's access token with whatever claims you want: admin, superuser, billing:write. full API access to every service that validates JWTs signed with that key
- Kubernetes ServiceAccount tokens: forge one for cluster-admin and you have root access to every pod, secret, and namespace in the cluster
- AWS Cognito, Azure AD, GCP Identity Platform all issue RS256 JWTs. forge them to access cloud resources without credentials
- service-to-service tokens are often long-lived. capture one now, factor the public key later, replay indefinitely. standard harvest-now-decrypt-later applied to identity tokens
## Code

`jwt_openssl_sign_verify.c` — `openssl_sign_sha_pem()` showing RS256/RS384/RS512
all routing to `EVP_PKEY_RSA` with `EVP_DigestSign`, and PS256/PS384/PS512
to `EVP_PKEY_RSA_PSS` — every JWT signing algorithm is RSA.
