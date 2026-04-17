#!/bin/bash
# release_signing_workflow.sh
#
# Debian archive Release-file signing pipeline. This is what runs on the
# ftp-master host at ftp-master.debian.org every few hours, and what
# Ubuntu's archive team runs on archive.ubuntu.com, and what every
# downstream derivative (Tails, Kali, Raspbian, PureOS, Astra Linux) runs
# for their own pocket of the apt universe.
#
# The underlying RSA + OpenPGP primitives live in `debian_apt_rsa.sh`;
# this is the orchestration on top.

set -euo pipefail

SUITE=${1:?suite required (e.g. bookworm, trixie, jammy)}
ARCHIVE_ROOT=/srv/ftp.debian.org/ftp
DISTS=${ARCHIVE_ROOT}/dists/${SUITE}
SIGNING_KEY="0x4CB50190207B4758A3F73A796ED0E7B82643E131"   # archive signing key
EMBARGOED_KEY="0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553" # security key

# ---- 1. Rebuild per-arch Packages / Sources indices ----
for arch in amd64 arm64 armel armhf i386 mips64el ppc64el riscv64 s390x source; do
    apt-ftparchive packages ${DISTS}/main/binary-${arch} \
        > ${DISTS}/main/binary-${arch}/Packages
    xz -fk ${DISTS}/main/binary-${arch}/Packages
    gzip -fk ${DISTS}/main/binary-${arch}/Packages
done

# ---- 2. Compose the Release file (hash index that apt pins on) ----
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=Debian \
    -o APT::FTPArchive::Release::Label=Debian \
    -o APT::FTPArchive::Release::Suite=${SUITE} \
    -o APT::FTPArchive::Release::Codename=${SUITE} \
    -o APT::FTPArchive::Release::Architectures="amd64 arm64 armel armhf i386 mips64el ppc64el riscv64 s390x source" \
    -o APT::FTPArchive::Release::Components="main contrib non-free non-free-firmware" \
    release ${DISTS} > ${DISTS}/Release

# ---- 3. Sign it.  Every apt client on Earth pins on this signature. ----
#
# InRelease = inline clearsigned (preferred since Debian 9)
gpg --batch --yes --local-user ${SIGNING_KEY} \
    --clearsign --digest-algo SHA512 \
    --output ${DISTS}/InRelease ${DISTS}/Release

# Release.gpg = legacy detached sig for apt < 1.1 on ancient derivatives
gpg --batch --yes --local-user ${SIGNING_KEY} \
    --detach-sign --armor --digest-algo SHA512 \
    --output ${DISTS}/Release.gpg ${DISTS}/Release

# ---- 4. Dual-sign stable-security and oldstable-security with the
#         security team's distinct RSA key (separated so that a
#         compromised archive signer cannot push emergency patches). ----
if [[ ${SUITE} =~ -security$ ]]; then
    gpg --batch --yes --local-user ${EMBARGOED_KEY} \
        --clearsign --digest-algo SHA512 \
        --output ${DISTS}/InRelease.security ${DISTS}/Release
fi

# ---- 5. Publish via rsync to mirror network ----
rsync -aH --delete ${DISTS}/ \
    push-mirrors.debian.org::debian-dists/dists/${SUITE}/

# Every `apt update` across hundreds of millions of Debian/Ubuntu hosts
# verifies exactly these RSA signatures before accepting any Packages
# index update. A factoring break lets an adjacent network attacker
# (cafe wifi, hostile ISP, nation-state-on-path) inject arbitrary
# malicious package indices + .deb files signed under the archive key,
# achieving silent root on every box that runs apt update.
