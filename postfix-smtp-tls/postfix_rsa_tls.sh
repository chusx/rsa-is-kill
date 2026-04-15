#!/bin/bash
# postfix_rsa_tls.sh
#
# Postfix MTA — RSA TLS server certificates for SMTP and STARTTLS.
# Sources:
#   - Postfix TLS readme: http://www.postfix.org/TLS_README.html
#   - postconf(5) man page: smtpd_tls_cert_file, smtpd_tls_key_file
#   - Dan Bernstein's qmail / djbdns vs Postfix TLS discussion
#
# Postfix is the world's most deployed mail transfer agent (MTA).
# It handles SMTP and LMTP for most of the internet's email infrastructure:
#   - Default MTA on Red Hat, CentOS, Fedora, Ubuntu, Debian
#   - Used by Google, Facebook, Yahoo, Amazon SES in their MTA infrastructure
#   - ISPs, universities, government agencies for inbound/outbound email
#   - Any Linux server running a mail server is almost certainly Postfix
#
# Postfix TLS configuration uses RSA certificates for:
#   - smtpd (inbound SMTP): STARTTLS and SMTPS (port 465)
#   - smtp (outbound): opportunistic TLS to other MTAs
#
# The Postfix TLS certificate is either:
#   a) A self-signed RSA-2048 cert (default for many deployments)
#   b) A CA-signed cert from Let's Encrypt, DigiCert, etc. (RSA-2048 or ECDSA P-256)
#   c) An internally-issued cert from the organization's CA
#
# MTA-STS (RFC 8461) and DANE/TLSA (RFC 7671) publish the expected TLS certificate
# via DNS. Both can constrain the expected RSA certificate public key.
# An attacker who factors the MTA's RSA-2048 key can bypass both protections.

set -euo pipefail

# =============================================================================
# generate_postfix_tls_cert() — generate RSA-2048 TLS cert for Postfix
# =============================================================================
generate_postfix_tls_cert() {
    local domain="${1:-mail.example.com}"
    local cert_dir="${2:-/etc/postfix/certs}"
    local key_file="$cert_dir/smtp.key"
    local cert_file="$cert_dir/smtp.crt"

    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"

    echo "[*] Generating RSA-2048 key for Postfix TLS"
    openssl genrsa -out "$key_file" 2048
    chmod 600 "$key_file"

    echo "[*] Generating self-signed certificate for: $domain"
    openssl req -new -x509 -key "$key_file" \
        -out "$cert_file" \
        -days 3650 \
        -subj "/CN=$domain/O=Mail Server/C=US" \
        -addext "subjectAltName=DNS:$domain,DNS:smtp.$domain"

    echo "[+] Certificate: $cert_file"
    echo "[+] Private key: $key_file"

    # Show the public key modulus (2048-bit, the CRQC input)
    openssl x509 -in "$cert_file" -noout -text | grep -A3 "Public-Key:"
}

# =============================================================================
# configure_postfix_tls() — configure Postfix main.cf for TLS
# =============================================================================
configure_postfix_tls() {
    local cert_file="${1:-/etc/postfix/certs/smtp.crt}"
    local key_file="${2:-/etc/postfix/certs/smtp.key}"

    echo "[*] Configuring Postfix TLS in main.cf"
    cat >> /etc/postfix/main.cf << EOF

# TLS configuration (RSA-2048 certificate)
# Certificate public key visible to any SMTP client during STARTTLS handshake
smtpd_tls_cert_file = $cert_file
smtpd_tls_key_file = $key_file
smtpd_tls_security_level = may          # opportunistic TLS
smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache

# Outbound TLS
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

# Cipher list — includes RSA ciphers, excludes only RC4/export
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_exclude_ciphers = aNULL, eNULL, EXPORT, RC4, MD5, PSK, SRP

# TLS version
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
EOF
    echo "[+] Postfix TLS configured"
}

# =============================================================================
# generate_dane_tlsa_record() — generate DANE TLSA record for Postfix cert
# =============================================================================
generate_dane_tlsa_record() {
    local cert_file="${1:-/etc/postfix/certs/smtp.crt}"
    local selector="${2:-1}"      # 1 = SubjectPublicKeyInfo
    local match_type="${3:-2}"    # 2 = SHA-512 hash

    echo "[*] DANE TLSA record (publishes RSA-2048 public key in DNS)"
    echo "[*] The TLSA record pins the RSA-2048 key hash in DNSSEC-signed DNS."
    echo "[*] An attacker who factors the RSA key bypasses DANE constraint."
    echo ""

    # TLSA usage 3 1 1 = DANE-EE, SubjectPublicKeyInfo, SHA-256
    openssl x509 -in "$cert_file" -noout -pubkey | \
        openssl pkey -pubin -outform DER | \
        openssl dgst -sha256 -hex | \
        awk '{print "_25._tcp.mail.example.com. IN TLSA 3 1 1 " $2}'
}

# =============================================================================
# check_mta_sts_policy() — check MTA-STS policy for a domain
# =============================================================================
check_mta_sts_policy() {
    local domain="${1:-example.com}"

    echo "[*] MTA-STS policy for: $domain"
    echo "[*] MTA-STS pins the allowed certificates for incoming SMTP."
    echo "[*] An attacker with the RSA private key can forge the pinned cert."

    # MTA-STS policy is at https://mta-sts.{domain}/.well-known/mta-sts.txt
    curl -s "https://mta-sts.$domain/.well-known/mta-sts.txt" 2>/dev/null | head -10 || \
        echo "[-] No MTA-STS policy (or curl not available)"
}

# =============================================================================
# show_smtp_tls_cert() — connect to an SMTP server and show its RSA cert
# =============================================================================
show_smtp_tls_cert() {
    local smtp_host="${1:-mail.example.com}"
    local smtp_port="${2:-25}"

    echo "[*] Fetching TLS certificate from SMTP server: $smtp_host:$smtp_port"
    echo "[*] This is the RSA-2048 public key that CRQC would factor."

    # Use openssl s_client with STARTTLS to get the certificate
    echo "QUIT" | openssl s_client \
        -connect "$smtp_host:$smtp_port" \
        -starttls smtp \
        -showcerts 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null | \
        grep -E "(Subject:|Issuer:|Public-Key:|RSA|Exponent)"
}

# SMTP TLS deployment context:
#
# Almost all SMTP servers present RSA-2048 certificates:
#   - Postfix defaults to RSA-2048 (OpenSSL default)
#   - Exim defaults to RSA-2048
#   - Exchange Server: RSA-2048 from enterprise CA
#   - Sendmail: RSA-2048 (where still deployed)
#
# SMTP email is hop-by-hop encrypted: each MTA decrypts and re-encrypts.
# Breaking the RSA key of any intermediate MTA enables:
#   - Decrypt traffic to/from that MTA (TLS is terminated at each hop)
#   - Impersonate the MTA to its peers (forge SMTP connections)
#   - MITM email on that delivery hop
#
# For inbound mail (e.g., a corporate mail server's MX record):
#   - Factor the RSA-2048 cert public key (available from port 25 STARTTLS handshake)
#   - MITM connections from other MTAs delivering mail to this server
#   - Read incoming email in transit (including attachments, metadata)
#   - Modify email content before it reaches the recipient's mailbox
#
# STARTTLS downgrade attacks already allow passive surveillance on MTAs that
# don't enforce TLS. For MTAs that DO enforce TLS (DANE, MTA-STS, mandatory TLS),
# breaking the RSA key is the attack — it bypasses the enforcement.
#
# Government mail servers, corporate headquarters MX records, encrypted email
# gateways — all use Postfix or Exchange with RSA-2048 certificates on port 25.
# The public key is available to anyone who connects to port 25.
