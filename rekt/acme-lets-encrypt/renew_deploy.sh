#!/usr/bin/env bash
# renew_deploy.sh — cron-driven ACME renewal + fleet deploy
#
# This is the shape of the wrapper that every org-scale Let's Encrypt
# user runs around an ACME client (certbot / acme.sh / lego / step).
# The RSA crypto (CSR + account key) lives in the ACME client; this
# script is what schedules, rotates, and distributes the resulting cert
# chain to the fleet of load balancers / origin servers / app pods.

set -euo pipefail

DOMAINS=(api.example.com www.example.com cdn.example.com)
CERT_DIR=/etc/letsencrypt/live
ACME_CLIENT=/usr/bin/certbot
ACCOUNT_KEY=/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/HASH/private_key.json
FLEET_HOSTS=(nginx-edge-{01..08}.prod lb-{01..04}.prod)

# 1. Renew only if <30d to expiry. certbot uses the account RSA-2048
#    key to authenticate to Let's Encrypt and an RSA-2048 (or 4096) CSR
#    key per domain set.
for d in "${DOMAINS[@]}"; do
  "$ACME_CLIENT" renew --cert-name "$d" \
      --key-type rsa --rsa-key-size 2048 \
      --deploy-hook "/usr/local/sbin/acme-reload-$d" \
      --no-random-sleep-on-renew
done

# 2. Atomically distribute renewed chain to every edge. Uses rsync over
#    SSH (SSH host key also RSA by default — see openssh-host-keys/).
for host in "${FLEET_HOSTS[@]}"; do
  rsync -a --chmod=F0644 \
        "$CERT_DIR"/api.example.com/{fullchain.pem,privkey.pem} \
        "deploy@$host:/etc/nginx/tls/api.example.com/"
  ssh "deploy@$host" sudo systemctl reload nginx
done

# 3. Invalidate upstream caches / CDN origin pulls so the new cert
#    picks up at every edge within a minute.
curl -fsS -X POST "https://api.cdn.example.com/v1/origin-cert-reload" \
     -H "Authorization: Bearer $CDN_ADMIN_TOKEN" \
     -d "{\"domains\": $(printf '%s\n' "${DOMAINS[@]}" | jq -R . | jq -s .)}"

# 4. Report cert SHAs to observability for anomaly detection
#    (sudden issuer change, sudden key-size change = investigate).
for d in "${DOMAINS[@]}"; do
  spki=$(openssl x509 -in "$CERT_DIR/$d/fullchain.pem" -noout \
         -pubkey | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)
  logger -t acme-rotate "domain=$d spki=$spki issuer=$(openssl x509 -in \
         "$CERT_DIR/$d/fullchain.pem" -noout -issuer)"
done
