# acme-lets-encrypt — RSA account keys in ACME/Let's Encrypt (300M+ domains)

**Repository:** certbot (certbot/certbot), acme.sh, golang.org/x/crypto/acme 
**Industry:** Web PKI — essentially the entire HTTPS internet 
**Algorithm:** RSA-2048 (ACME account keys, Certbot default before 2021; certificate RSA-2048 for older configs) 

## What it does

ACME (RFC 8555) is the protocol Let's Encrypt uses to issue free TLS certificates.
The client registers with an account key and signs every API request with it using
JWS RS256 (RSASSA-PKCS1-v1_5 / SHA-256). The ACME server verifies this signature to
authenticate all certificate operations — issuance, renewal, revocation.

Certbot used RSA-2048 as the default account key type until 2021. Even after switching
to ECDSA P-256 as default, existing accounts keep their RSA-2048 account keys indefinitely
unless manually rotated (most operators never rotate). `acme.sh` defaults to RSA.

The account key is stored at `~/.config/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/{thumbprint}/private_key.json` — a JWK JSON file whose `n` field is the RSA-2048 modulus. This file is commonly backed up with the webserver config. The Let's Encrypt server also stores the account public key.

Let's Encrypt has issued 2+ billion certificates since 2015 and currently serves ~60% of
HTTPS traffic on the internet. Certbot is the most deployed ACME client.

## Why it's stuck

- RFC 8555 defines `RS256` (RSA) and `ES256` (ECDSA) as JWS algorithm IDs for account
 keys. There is no `ML-DSA` algorithm ID registered. Adding one requires an RFC update
 and all ACME implementations (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services)
 updating simultaneously.
- ACME account key rotation is a manual operation. Most operators configure Certbot
 once and never touch the account key again. The `certbot update_account` command
 requires deliberate action.
- Certbot switched to ECDSA default in 2021 but this only affects NEW account key
 creation. Existing deployments with RSA-2048 account keys are unaffected.
- The certificate itself (the 90-day one) isn't the primary risk here — short expiry
 helps. The account key is long-lived and authorizes all certificate operations.

## impact

the 90-day cert rotation people keep pointing to as "post-quantum" isn't the problem.
the account key is. it's been sitting in the same JSON file for years.

- derive the RSA-2048 account private key from the JWK public key (in `private_key.json`
 or from any recorded ACME newAccount request). now authenticate to Let's Encrypt as
 that account. call ACME revocation (POST /acme/revoke-cert) for every certificate on
 the account. immediate DoS for every HTTPS domain on that certbot deployment.
- for the offensive use case (not just DoS): revoke current cert, wait for Certbot
 auto-renewal to fail (it will, since domain validation hasn't been re-done), then
 use your account credentials to request a new certificate. this requires also having
 DNS or HTTP control over the domain to pass validation. but if you have that plus the
 account key, you can issue a valid Let's Encrypt cert for the domain and use it for MITM.
- for mass operators: CDNs, hosting providers, and SaaS platforms often use a single
 ACME account for thousands of customer domains. one account key compromise = certificate
 control for all customer domains on that deployment.
- HNDL for account keys: record ACME TLS traffic from certbot deployments. the account
 key JWS is in every ACME API request. factor the RSA-2048 key later. the account is
 likely still active because nobody rotates these.
- acme.sh is widely deployed in corporate environments with RSA default. DATEV, Oracle
 Cloud, and basically every company running self-managed nginx has an acme.sh RSA-2048
 account key somewhere.

## Code

`acme_rsa_account.py` — `jwk_from_rsa_key()` (JWK with RSA-2048 n/e fields — the factoring break
input), `acme_sign_request()` (JWS RS256 = RSASSA-PKCS1-v1_5 / SHA-256 over ACME request),
`generate_rsa_account_key()` (RSA-2048 key generation, certbot default), `acme_get_thumbprint()`
(SHA-256 of canonical JWK, account identifier). Let's Encrypt deployment scale and HNDL
attack context in comments.
