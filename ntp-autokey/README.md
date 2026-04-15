# NTP Autokey — RSA Time Server Authentication

**Source:** https://www.ntp.org / https://gitlab.com/NTPsec/ntpsec 
**File:** `ntpd/ntp_crypto.c` (ntp.org reference impl) 
**License:** NTP License (BSD-like)

## what it does

NTP Autokey (RFC 5906) authenticates NTP time servers using RSA certificates and signatures. Every NTP client that uses Autokey verifies the server's RSA signature before accepting time updates.

## impact

time is a dependency of basically every other security mechanism. NTP Autokey uses RSA to authenticate time servers. also the example key size in the code is RSA-512, which is just a fun detail.

- break Autokey and push false time to clients. shift clocks forward to make valid TLS certificates appear expired, or back to make revoked ones appear valid
- Kerberos has a 5-minute skew tolerance. push clocks far enough and all Kerberos tickets become invalid. enterprise authentication stops working
- TOTP codes are time-based. enough clock skew and 2FA codes stop matching. either you lock everyone out or you create a window where any code from a given time range works
- TLS certificate validity is time-bounded. CRLs have timestamps. audit logs use timestamps. manipulate authenticated NTP and the forensic record becomes unreliable
