# postfix-smtp-tls — RSA in Postfix SMTP TLS (the MTA that handles most of the internet's email)

**Repository:** postfix (postfix.org); http://www.postfix.org/TLS_README.html 
**Industry:** Internet email delivery — ISPs, universities, government, corporate 
**Algorithm:** RSA-2048 (default TLS certificate for smtpd STARTTLS; also common for smtp outbound TLS) 

## What it does

Postfix is the world's most deployed MTA (mail transfer agent). It's the default on RHEL,
Ubuntu, Debian, and most Linux distributions. It handles SMTP email delivery for ISPs,
universities, government agencies, and most self-hosted email infrastructure.

Postfix STARTTLS (port 25) and SMTPS (port 465) use OpenSSL with the certificate and key
configured via `smtpd_tls_cert_file` and `smtpd_tls_key_file` in main.cf. The default
certificate generated at installation is RSA-2048 (openssl genrsa 2048). Even when a
CA-signed cert is used, most admins use Let's Encrypt RSA-2048 (pre-2021 certbot default)
or ADCS-issued RSA-2048.

The RSA-2048 public key is in the TLS certificate, which is sent in the clear during the
STARTTLS handshake on port 25. It's visible to anyone who connects to the mail server's
port 25 — no authentication required. SMTP is intentionally open on port 25 to receive email.

DANE/TLSA records (RFC 7671) and MTA-STS (RFC 8461) publish the expected MTA certificate
in DNS to prevent STARTTLS downgrade attacks and certificate substitution. Both protections
rely on RSA: if you can forge the pinned RSA-2048 cert, you bypass both.

## Why it's stuck

- Postfix TLS calls OpenSSL. OpenSSL non-RSA support is experimental and not in any stable
 release used by any distribution's Postfix package.
- `smtpd_tls_cert_file` in main.cf expects a PEM certificate. There is no non-RSA certificate
 type in any public PKI or in OpenSSL stable APIs.
- Email delivery TLS is opportunistic (STARTTLS "may") for most servers, meaning TLS is
 attempted but not required. The security baseline is already lower than browser HTTPS.
- Coordinating a non-RSA migration for SMTP would require all major MTAs (Postfix, Exim,
 Exchange, Gmail) to support non-RSA cipher suites simultaneously for the transition to
 be meaningful — otherwise downgrade to RSA is trivial.

## impact

SMTP TLS is the encryption layer for email in transit between mail servers. the RSA key
is what makes that encryption mean anything.

- port 25 is open on every mail server. connect, do STARTTLS, get the RSA-2048 public
 key from the TLS certificate. no login, no authentication, publicly accessible. factor it.
- MitM SMTP connections to the target mail server. interception is hop-by-hop in email:
 the next MTA's RSA key is what's protecting delivery from the previous hop. break it and
 you can read every email delivered to that server before it hits the user's mailbox.
- for MTA-STS/DANE-protected domains: these protections exist to prevent STARTTLS
 downgrade (an attacker strips STARTTLS to force plaintext). they're the "we require
 TLS and pin the cert" option. if the RSA cert itself is broken, MTA-STS/DANE doesn't
 help — you have the real cert's private key, your MitM looks identical to the real server.
- government MX records: federal agencies (.gov, .mil), EU institutions, national government
 domains all have Postfix or Exchange MTA RSA-2048 certs visible on port 25. the public
 key is on Shodan, censys, and similar scan databases — no active scanning needed.
- email is used for password resets, MFA codes, wire transfer confirmations, contract
 delivery. MitM the MTA and you can intercept all of these in transit without touching
 the endpoint.

## Code

`postfix_rsa_tls.sh` — `generate_postfix_tls_cert()` (openssl genrsa 2048 + self-signed cert),
`configure_postfix_tls()` (main.cf smtpd_tls_cert_file / smtpd_tls_key_file),
`generate_dane_tlsa_record()` (TLSA record pinning RSA-2048 SubjectPublicKeyInfo SHA-256),
`show_smtp_tls_cert()` (openssl s_client -starttls smtp to extract server cert).
MTA-STS bypass analysis and port 25 public key exposure context.
