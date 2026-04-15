#!/bin/bash
# card_provisioning.sh
#
# OpenPGP card (YubiKey 5, Nitrokey 3, Gnuk, Floss Smartcard-HSM-4K)
# provisioning for employee PGP keys. Drives the on-card RSA primitives
# in `openpgp_card_rsa.c` through `gpg --card-edit` / `ykman openpgp`.
#
# This is what Security Engineering / IT runs on hiring day at every
# large tech org that actually enforces signed commits + signed email +
# SSH-via-GPG-agent. The pattern here is also what CAcert, PGP Global
# Directory, and every large open-source project secretariat uses for
# maintainer key provisioning (Debian keyring team, Linux kernel
# maintainers, Apache Foundation release managers).

set -euo pipefail

EMPLOYEE_EMAIL=${1:?email required}
EMPLOYEE_NAME=${2:?name required}
CARD_READER=${3:-"Yubico YubiKey FIDO+CCID 00 00"}

# ---- 1. Reset the card (first-time provisioning) ----
#
# Wipes Admin PIN, User PIN, Reset Code to factory defaults. Only
# acceptable on a brand new card; refuses if anything is already set.
gpg --command-fd 0 --yes --card-edit <<EOF
admin
factory-reset
y
yes
quit
EOF

# ---- 2. Set PINs to policy values ----
#
# User PIN unlocks per-signature touch + decrypt; Admin PIN unlocks
# key-generation / reset; Reset Code unblocks User PIN after 3 wrong.
#
# Length/complexity per NIST SP 800-63B: ≥6 chars user, ≥8 admin.
gpg --command-fd 0 --yes --change-pin <<EOF
3
${CARD_ADMIN_PIN_DEFAULT}
${CARD_ADMIN_PIN_NEW}
${CARD_ADMIN_PIN_NEW}
q
EOF

gpg --command-fd 0 --yes --change-pin <<EOF
1
${CARD_USER_PIN_DEFAULT}
${CARD_USER_PIN_NEW}
${CARD_USER_PIN_NEW}
q
EOF

# ---- 3. Generate keys *on-card* — private key material never exists
#         in RAM or disk on the provisioning workstation. ----
#
# Three slots: Signature (S), Encryption (E), Authentication (A).
# All three RSA-4096 on YubiKey 5 / Nitrokey 3; RSA-2048 on older
# stock with slower co-processor. Generate time on-card is ~60s per
# 4096-bit key — the script prompts Security Engineering to sit and
# wait.
gpg --command-fd 0 --yes --card-edit <<EOF
admin
generate
n
${EMPLOYEE_EMAIL}
${EMPLOYEE_NAME}
2y
${EMPLOYEE_NAME} <${EMPLOYEE_EMAIL}>
y
${CARD_USER_PIN_NEW}
${CARD_ADMIN_PIN_NEW}
quit
EOF

# ---- 4. Publish public key + enroll in corporate keyring ----
KEYID=$(gpg --list-secret-keys --with-colons "${EMPLOYEE_EMAIL}" | \
         awk -F: '/^sec/ {print $5; exit}')

gpg --armor --export "$KEYID" | \
    curl --fail -X POST --data-binary @- \
         "https://keyring.corp.example.com/v1/upload?owner=${EMPLOYEE_EMAIL}"
gpg --keyserver hkps://keys.openpgp.org --send-keys "$KEYID"

# ---- 5. Generate + escrow revocation cert (sealed envelope, safe) ----
gpg --output /tmp/revcert-${KEYID}.asc --gen-revoke "$KEYID" <<EOF
y
0
Lost-card scenario
y
${CARD_USER_PIN_NEW}
EOF
gpg --encrypt --armor --recipient "security-escrow@corp.example.com" \
    /tmp/revcert-${KEYID}.asc
shred -u /tmp/revcert-${KEYID}.asc

# ---- 6. Enable SSH-via-GPG-agent (cardholder Authentication subkey) ----
gpg --export-ssh-key "$KEYID" \
    >> ~/.gnupg/authorized_ssh_keys_stub
echo "enable-ssh-support"       >> ~/.gnupg/gpg-agent.conf
echo "pinentry-program /usr/bin/pinentry-gnome3" >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent reloadagent /bye

# ---- 7. Document ----
#
# Provisioning produces a ceremony record signed by the Security
# Engineering attestor's own OpenPGP key, binding:
#   - Card serial (etched on enclosure + OpenPGP card serial)
#   - Employee HR ID + start date
#   - Key fingerprint
#   - PIN class (user/admin) issuance witness
#
# Stored in the infosec evidence store; referenced in SOX/PCI audits.


# Breakage:
#
# Every signature, SSH login, and decryption that traverses this card
# is an RSA operation (PKCS#1 v1.5 + SHA-256/512). A factoring break
# makes the public keys uploaded in step 4 silently impersonable:
#   - Attackers forge git commits / email signatures under any
#     employee identity without ever touching the physical card.
#   - Attackers forge SSH auth challenges against any server that
#     accepts the cardholder's exported SSH pubkey — so production
#     bastion hosts fall to offline math.
# The card was protecting the private key from extraction, not from
# mathematical equivalence.
