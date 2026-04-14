# NTP Autokey — RSA Time Server Authentication

**Source:** https://www.ntp.org / https://gitlab.com/NTPsec/ntpsec  
**File:** `ntpd/ntp_crypto.c` (ntp.org reference impl)  
**License:** NTP License (BSD-like)

## what it does

NTP Autokey (RFC 5906) authenticates NTP time servers using RSA certificates and signatures. Every NTP client that uses Autokey verifies the server's RSA signature before accepting time updates.

## why attacking time synchronization is catastrophic

Time is a dependency of every other security system:

- **TLS certificates**: validity windows are time-based. Feed wrong time → all certs appear expired or not-yet-valid → HTTPS breaks everywhere.
- **Kerberos tickets**: 5-minute skew tolerance. Feed wrong time → all tickets invalid → enterprise authentication collapses.
- **TOTP / 2FA**: time-based one-time passwords. Feed wrong time → codes don't match → 2FA bypass or lockout.
- **Certificate revocation**: CRLs have timestamps. Feed wrong time → expired CRLs are trusted → revoked certs work.
- **Audit logs**: forensic evidence becomes untrusted if timestamps are manipulated.

The particularly insidious part: NTP Autokey in some deployments uses **RSA-512** (see the code — 512 bits is the example size). Classically broken, quantumly pulverized.

## migration status

NTPsec has deprecated Autokey in favor of NTS (RFC 8915), which uses TLS 1.3. But NTS still uses RSA/ECDSA certificates for the TLS layer. Most deployed NTP infrastructure still runs Autokey.
