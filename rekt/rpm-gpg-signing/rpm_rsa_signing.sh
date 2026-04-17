#!/bin/bash
# rpm_rsa_signing.sh
#
# Red Hat / Fedora / CentOS RPM package signing — RSA-4096 GPG keys.
#
# Sources:
#   - https://access.redhat.com/security/team/key/ (Red Hat GPG public keys)
#   - RPM GPG signing documentation: https://rpm-software-management.github.io/rpm/manual/
#   - Fedora packaging guidelines: https://docs.fedoraproject.org/en-US/packaging-guidelines/
#   - CentOS Stream signing: https://centos.org/keys/
#
# All RPM-based distributions (RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux,
# Oracle Linux, SUSE, openSUSE) sign their packages with GPG keys.
# The signing algorithm is RSA-4096 (for current Red Hat keys) or RSA-2048 (older).
#
# The public key is distributed with the OS and imported into the RPM keyring.
# When yum/dnf/zypper installs a package, RPM verifies the signature before installing.
# If the signature fails, the package manager refuses to install (unless --nogpgcheck).
#
# Red Hat signing keys (from access.redhat.com/security/team/key/):
#   RHEL 6,7,8,9: 4096-bit RSA (key IDs: FD431D51, 37017186, 77E79ABE, etc.)
#   Fedora 38-40:  4096-bit RSA
#   CentOS Stream: 4096-bit RSA
#
# The signing keys are held at Red Hat's secure signing infrastructure.
# The PUBLIC keys are distributed via:
#   - Bundled in the OS installer (rpm keyring)
#   - keyserver.redhat.com
#   - keys.fedoraproject.org
#   - The RPM packages themselves (/etc/pki/rpm-gpg/)
#
# An attacker who factors Red Hat's RSA-4096 signing key can sign arbitrary RPMs
# that will be accepted by all RHEL/CentOS/Fedora systems with no warning.

set -euo pipefail

# Red Hat GPG key ID for RHEL 9
REDHAT_KEY_ID="199E2F91FD431D51"
# Full fingerprint: 567E 347A D044 2268 10C1 3601 199E 2F91 FD43 1D51

# Fedora 40 key
FEDORA40_KEY_ID="A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"

# =============================================================================
# rpm_sign_package() — sign an RPM package with the build system's RSA-4096 key
# =============================================================================
rpm_sign_package() {
    local rpm_file="$1"
    local key_id="${2:-$REDHAT_KEY_ID}"

    echo "[*] Signing: $rpm_file"
    echo "[*] Key:     $key_id"

    # RPM signing uses the %_gpg_name macro to select the signing key
    # The key must be in the GPG keyring of the user running rpmsign
    rpmsign --addsign \
        --define "_gpg_name $key_id" \
        --define "_gpg_sign_cmd_extra_args --batch" \
        "$rpm_file"

    echo "[+] Signed: $rpm_file"
}

# =============================================================================
# rpm_verify_signature() — verify RSA-4096 GPG signature on RPM package
# =============================================================================
rpm_verify_signature() {
    local rpm_file="$1"

    echo "[*] Verifying: $rpm_file"

    # rpm -K checks the package signature against imported public keys
    # This calls into gpgme, which calls into libgcrypt/GnuPG
    # The signature is RSA-4096 PKCS#1 v1.5 (or v1.5 with SHA-256) over the package hash
    if rpm -K "$rpm_file" 2>&1 | grep -q "digests signatures OK"; then
        echo "[+] Signature OK: $rpm_file"
        return 0
    else
        echo "[-] Signature FAILED: $rpm_file"
        return 1
    fi
}

# =============================================================================
# import_redhat_gpg_keys() — import Red Hat public keys into RPM keyring
# =============================================================================
import_redhat_gpg_keys() {
    echo "[*] Importing Red Hat GPG public keys"

    # These keys ship with RHEL at /etc/pki/rpm-gpg/
    # The keys are RSA-4096 public keys — the CRQC input
    for keyfile in /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-*; do
        if [[ -f "$keyfile" ]]; then
            echo "[*] Importing: $keyfile"
            # gpg --import shows: pub   rsa4096 2021-09-09 [SC]
            #                     Key fingerprint = 567E 347A D044 2268...
            gpg --import "$keyfile" 2>/dev/null || true
            rpm --import "$keyfile"
        fi
    done
}

# =============================================================================
# batch_sign_repo() — sign all RPMs in a repository (build pipeline)
# =============================================================================
batch_sign_repo() {
    local repo_dir="$1"
    local key_id="${2:-$REDHAT_KEY_ID}"
    local signed=0
    local failed=0

    echo "[*] Batch signing all RPMs in: $repo_dir"
    echo "[*] Signing key: $key_id"

    # This is how Red Hat's actual build pipeline signs every package
    # The same key ID signs all packages for a given RHEL/Fedora release
    find "$repo_dir" -name "*.rpm" | while read -r rpm; do
        if rpm_sign_package "$rpm" "$key_id"; then
            ((signed++)) || true
        else
            ((failed++)) || true
            echo "[-] Failed to sign: $rpm"
        fi
    done

    echo "[+] Signed: $signed packages, failed: $failed"
}

# =============================================================================
# show_rpm_signature_info() — display RSA key info from a signed RPM
# =============================================================================
show_rpm_signature_info() {
    local rpm_file="$1"

    echo "[*] Signature info for: $rpm_file"

    # rpm -qpi shows the GPG key ID used for signing
    rpm -qpi "$rpm_file" 2>/dev/null | grep -E "(Signature|Build|Key)"
    # Example output:
    #   Signature   : RSA/SHA256, Tue 05 Mar 2024 12:34:56 UTC, Key ID 199e2f91fd431d51
    #   Build Date   : Mon 04 Mar 2024 08:00:00 UTC
    #   Build Host   : buildvm.fedoraproject.org

    # The Key ID (last 16 hex chars of the fingerprint) maps to the RSA-4096 public key
    # The full public key is at: https://access.redhat.com/security/team/key/
    # And locally at: /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
    echo ""
    echo "[*] RSA-4096 public key (the CRQC input):"
    rpm --import --test /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release 2>/dev/null || true
    gpg --list-keys "$REDHAT_KEY_ID" 2>/dev/null | head -5
}

# Usage example:
# rpm_sign_package mypackage-1.0-1.el9.x86_64.rpm
# rpm_verify_signature mypackage-1.0-1.el9.x86_64.rpm
# batch_sign_repo /mnt/repo/RHEL9/x86_64/

# ATTACK SCENARIO NOTES:
#
# The Red Hat RSA-4096 public key for RHEL 9 is at:
#   https://access.redhat.com/security/team/key/
#   /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release (on every RHEL 9 system)
#
# It's RSA-4096 (not -2048). Shor's algorithm works on RSA-4096 too.
# The qubit requirement is higher (~8192 logical qubits vs ~4096 for RSA-2048),
# but the algorithm is the same.
#
# With the private key derived from the public key:
#   1. Sign any RPM with: rpmsign --addsign --define "_gpg_name $KEY_ID" evil.rpm
#   2. Push to a mirror, or put in a local yum repo with a valid repodata/repomd.xml
#   3. Any RHEL 9 system that installs from that repo will accept the package
#   4. The RPM can be anything: a kernel module, a systemd service, a cron job
#
# This is the supply chain attack that mirrors the SolarWinds and 3CX scenarios,
# but doesn't require compromising Red Hat's build infrastructure.
# It requires only the public key (public) and a CRQC.
#
# 500M+ RHEL/CentOS/Fedora/Rocky/Alma systems are in scope.
