# OpenDKIM — RSA-SHA256 Email Signing

**Source:** https://github.com/trusteddomainproject/OpenDKIM  
**File:** `opendkim/opendkim.c`  
**License:** BSD-3-Clause / Sendmail Open Source License

## what it does

DKIM (DomainKeys Identified Mail) authenticates outbound email by signing selected message headers and the body hash with the sending domain's private key. The public key is published in DNS. Every receiving MTA verifies the signature. OpenDKIM is the most widely deployed DKIM implementation.

## why is this hella bad

- `dkimf_sign[]` maps human-readable algorithm names to constants — only `rsa-sha1` and `rsa-sha256` exist. There is no PQC entry.
- The signing algorithm is a global configuration value (`conf_signalg`) assigned to every message. There is no per-recipient or per-domain algorithm agility.
- Forging a DKIM signature bypasses anti-phishing protections (DMARC). A CRQC can forge the RSA signature on any email, making phishing and spoofing indistinguishable from legitimate mail.
- The problem is ecosystem-wide: even if OpenDKIM added ML-DSA, every receiving MTA in the world needs to support PQC DKIM verification before a sender can migrate. No PQC DKIM RFC has been published.
- Billions of DKIM public keys are published in DNS as RSA-2048 TXT records. Rotating all of them requires coordinated action across every email-sending domain.

## migration status

No PQC DKIM RFC. No IETF working group actively standardizing it as of 2026. OpenDKIM project is in maintenance mode.
