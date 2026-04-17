#!/bin/bash
# dnf_yum_verify_flow.sh
#
# How `dnf` / `yum` / `rpm` actually invoke the RSA verification path
# from `rpm_rsa_signing.sh` on every package install across RHEL /
# Rocky Linux / AlmaLinux / Fedora / CentOS Stream / Amazon Linux /
# Oracle Linux / SUSE Linux Enterprise.
#
# Every `dnf install`, `yum update`, or `rpm -ivh` on a supported
# machine runs through this code path. Roughly ~70% of enterprise
# Linux servers globally; every Amazon Linux 2 + AL2023 EC2 instance;
# every RHEL UBI container layer built in docker.io/redhat/ and
# quay.io/ubi* pulls.

set -euo pipefail

# ---- 1. Importing vendor RSA keys into the rpm keyring ----
#
# The first thing a fresh install does is import the vendor's RSA
# public signing key. This becomes the trust anchor for every
# subsequent package install.
#
# Real-world key imports on a fresh Rocky Linux box:
sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial        # Rocky Linux Release Engineering, RSA-4096
sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release       # Red Hat Release, RSA-4096 (for UBI + cross-RHEL sync)
sudo rpm --import https://download.docker.com/linux/centos/gpg      # Docker CE, RSA-4096
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc # Microsoft CNB + .NET + mssql-tools, RSA-4096
sudo rpm --import https://nvidia.github.io/nvidia-docker/gpgkey     # NVIDIA Container Toolkit, RSA-4096
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key   # Jenkins LTS, RSA-4096
sudo rpm --import https://packages.fluentbit.io/fluentbit.key       # Fluent Bit telemetry, RSA-4096

# ---- 2. Config /etc/dnf/dnf.conf + repo files force signature checks ----
#
# Policy:
cat <<'EOF' | sudo tee /etc/dnf/dnf.conf >/dev/null
[main]
gpgcheck=1                      # every package must be RSA-signed
localpkg_gpgcheck=1             # even locally dropped .rpm files
repo_gpgcheck=1                 # per-repo metadata signature too
installonly_limit=5
clean_requirements_on_remove=True
best=True
skip_if_unavailable=False
EOF

# ---- 3. A typical install traces through rpm RSA verify 3 times per package ----
#
# - .repo metadata (repomd.xml) → .repo.asc RSA sig verified (repo_gpgcheck=1)
# - .rpm lead+header lookup     → leading PGP header block RSA-verified
# - .rpm payload (cpio.xz)      → trailing signature-header RSA-verified
#
# All three verifications run through librpm's `rpmVerifySignatures`
# path, which is exactly the primitive wrapped by `rpm_rsa_signing.sh`.
sudo dnf -y install --refresh nginx

# ---- 4. Nightly automated security updates on hardened fleets ----
#
# RHEL's `dnf-automatic` timer or SUSE's `patchd` daemon auto-applies
# signed security errata without operator intervention. CISA KEV /
# FedRAMP mandates this for federal-civilian tenants. The entire
# chain of trust from "CVE fix → RHEL errata RHSA → package signed
# by Red Hat IT release engineering" rests on that RSA-4096 signing
# key held in a quorum-access HSM inside Red Hat's release plant.
sudo systemctl enable --now dnf-automatic.timer

# ---- 5. Vendor publishing path ----
#
# On the upstream side, release engineering runs the primitive in
# `rpm_rsa_signing.sh`:
#
#   rpm --addsign --define="%_signature gpg" \
#       --define="%_gpg_name Rocky Linux Release Eng" \
#       package-1.2.3-1.el9.x86_64.rpm
#
# The key lives in an HSM-backed gnupg smartcard; sign ceremony is
# quorum-attended (Rocky Foundation Release Committee, Red Hat
# "ir-r" team, SUSE "packman" signer group).

# ---- Breakage ----
#
# Every `dnf install` on every production RHEL-family box verifies
# an RSA-4096 signature chain rooted at the vendor's release
# signing key. A factoring attack against that key lets an attacker:
#
#   - Distribute malicious `kernel`, `openssl`, `sudo`, `dbus`,
#     `systemd` packages through compromised mirrors — RPM's
#     signature check passes and `dnf upgrade` happily installs
#     them.
#   - Push a poisoned update through `dnf-automatic` and reach
#     every federal RHEL box that has FedRAMP auto-patching
#     enabled in a single update cycle.
#
# There is no in-band mechanism for RPM to reject a package signed
# with the official key — revocation of the vendor's signing key
# requires out-of-band notification and manual `rpm --erase` of
# the keyring entry. Supply-chain incident-response for a factoring
# break is measured in days-to-weeks of manual cleanup per affected
# enterprise.
