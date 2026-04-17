# OpenDKIM — RSA-SHA256 Email Signing

**Source:** https://github.com/trusteddomainproject/OpenDKIM 
**File:** `opendkim/opendkim.c` 
**License:** BSD-3-Clause / Sendmail Open Source License

## what it does

DKIM (DomainKeys Identified Mail) authenticates outbound email by signing selected message headers and the body hash with the sending domain's private key. The public key is published in DNS. Every receiving MTA verifies the signature. OpenDKIM is the most widely deployed DKIM implementation.

## impact

DKIM is how receiving mail servers verify that an email actually came from the sending domain. the public key is in DNS, published for anyone to query. the input an attacker needs is freely available in public DNS.

- forge DKIM signatures for any domain with RSA-1024 or RSA-2048 keys. send email that passes DKIM verification appearing to come from president@whitehouse.gov, ceo@bigbank.com, security-alerts@your-bank.com, whatever
- DMARC and BIMI both depend on DKIM. forge DKIM, pass DMARC checks, get the little verified brand logo in the recipient's mail client. phishing with full authentication stamps
- RSA-1024 DKIM keys are still widely deployed and are classically weak. no factoring break needed for those, just compute
- the receiving server has no way to know the signature is forged. SPF alignment passes. DMARC passes. the email looks completely legitimate at every check
