# piv-cac-smartcard — RSA-2048 in US government identity cards

**Software:** OpenSC (OpenSC/OpenSC) — reference PIV/CAC smart card library  
**Hardware:** PIV smart cards (GSA USAccess), CAC (DoD), PIV-I (state/local gov)  
**Algorithm:** RSA-2048 (dominant), some RSA-1024 (legacy CAC), ECDSA P-256/P-384 (newer)  
**PQC migration plan:** None — SP 800-73-5 (PQC PIV interface spec) not yet published; no procurement timeline

## What it does

PIV (Personal Identity Verification, FIPS 201) is the US federal identity
standard. Every federal employee and contractor carries a PIV card with:

- RSA-2048 key in slot **9A** (PIV Authentication) — for Windows login, SSH, VPN
- RSA-2048 key in slot **9C** (Digital Signature) — for email signing (S/MIME)
- RSA-2048 key in slot **9D** (Key Management) — for email encryption
- RSA-2048 key in slot **9E** (Card Authentication) — for physical door access

~5 million PIV cards + ~3.5 million DoD CAC cards = ~8.5 million credentials.

The PIV algorithm ID for RSA-2048 is `0x07` (`PIV_ALG_RSA_2048`). The private
key never leaves the card, but the public key is in the certificate stored on
the card and often published in LDAP/AD.

## Why it's stuck

- **SP 800-73-4** (PIV Command Interface) defines algorithm IDs — no PQC IDs exist
- **SP 800-73-5** (PQC extension) has been in draft status; NIST has not finalized it
- **GSA procurement**: replacing ~8.5M physical cards requires funding, card
  manufacturer certification (FIPS 140-3), and agency-wide rollout
- **Infrastructure**: Windows Hello for Business, PIV middleware (OpenSC,
  Microsoft Smart Card Minidriver), macOS CryptoTokenKit — all need PQC updates
- **FIPS 201-3 (2022)** mentioned PQC in passing but set no deadline

## why is this hella bad

PIV/CAC cards are the keys to the US federal government. Breaking RSA-2048 authentication means:

- **Forge any federal employee's identity**: PIV slot 9A certificate is in AD LDAP (public) → CRQC recovers private key → get a Kerberos TGT for any federal employee → access every system they have access to
- **Break Windows Hello for Business**: WHfB uses hardware RSA keys in TPMs for certificate-based auth → same attack chain as PKINIT (see kerberos-pkinit/)
- **DoD CAC compromise**: ~3.5M military credentials → access to military systems, classified networks (SIPRNet uses CAC for authentication)
- **Physical access control bypass**: PIV slot 9E (Card Authentication) is used for building access. Forge it → enter any federally-controlled building with a PIV-controlled door
- 8.5 million compromised credentials spanning all cabinet departments, intelligence agencies, and DoD

## Code

`opensc_piv_rsa.c` — `piv_general_authenticate()` (RSA sign/decrypt via
GENERAL AUTHENTICATE APDU), PIV algorithm ID table showing `0x07` = RSA-2048,
and the capability flags `CI_NO_RSA2048` / `CI_RSA_4096`.
