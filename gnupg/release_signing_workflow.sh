#!/bin/bash
# release_signing_workflow.sh
#
# How real open-source projects use GnuPG (RSA primitives in
# `keygen_rsa_defaults.c`) to sign tarball releases. This is the
# workflow that runs for:
#   - Linux kernel (stable-queue release manager key → kernel.org),
#     Greg KH + Linus sign tags and tarballs
#   - GNU project releases (autoconf, bash, coreutils, emacs, gcc)
#     uploaded to ftp.gnu.org with detached .sig
#   - Apache Foundation PMC release-manager keys signing each ASF
#     release (RM fingerprint in KEYS file at root of dist path)
#   - PostgreSQL, Nginx, MariaDB, Redis, OpenSSL, OpenSSH source
#     releases
#
# Downstream package builders (Debian dak, Fedora rpmbuild,
# Homebrew/--HEAD builds, nixpkgs fetchurl hashes) treat these
# detached signatures as the ground truth for release authenticity.

set -euo pipefail

PROJECT=${1:?project name}
VERSION=${2:?version}
RM_KEYID=${3:?release-manager fingerprint}
DIST_DIR=${4:-"./dist"}

TARBALL="${PROJECT}-${VERSION}.tar.xz"
SHA256_FILE="${TARBALL}.sha256"
SIG_FILE="${TARBALL}.sig"
ASC_FILE="${TARBALL}.asc"

cd "${DIST_DIR}"

# ---- 1. Reproducible tarball ----
#
# `--mtime`, `--owner 0 --group 0`, `--sort=name` on GNU tar; or
# `SOURCE_DATE_EPOCH` + pax tar. Hash must be deterministic so
# multiple committers can independently check.
test -f "${TARBALL}" || { echo "missing ${TARBALL}"; exit 2; }

sha256sum "${TARBALL}" > "${SHA256_FILE}"

# ---- 2. Detached binary signature (.sig) + ASCII (.asc) ----
#
# Two files because downstream tooling is split: dpkg-source looks
# for .asc, `gpg --verify file.sig file` is the standard UNIX path.
gpg --batch --yes \
    --local-user "${RM_KEYID}" \
    --digest-algo SHA512 \
    --detach-sign --output "${SIG_FILE}" "${TARBALL}"

gpg --batch --yes \
    --local-user "${RM_KEYID}" \
    --digest-algo SHA512 \
    --detach-sign --armor --output "${ASC_FILE}" "${TARBALL}"

# ---- 3. Clearsign the SHA256 checksum file ----
#
# Many ecosystems prefer a single clearsigned manifest (nginx,
# OpenSSL) that covers all shipped files with their hashes.
gpg --batch --yes \
    --local-user "${RM_KEYID}" \
    --digest-algo SHA512 \
    --clearsign --output "${SHA256_FILE}.asc" "${SHA256_FILE}"

# ---- 4. Multi-signer rings: ASF / kernel / Debian style ----
#
# Many projects require N-of-M RM signatures on a release.  This
# script is invoked once per RM on their own laptop; the resulting
# .sig files are concatenated into a single detached signature file
# that verifiers accept when *any one* is valid (or, in the Debian
# dak case, when the set meets the keyring's threshold).
if [[ -n "${SECONDARY_RM_KEYID:-}" ]]; then
    gpg --batch --yes \
        --local-user "${SECONDARY_RM_KEYID}" \
        --digest-algo SHA512 \
        --detach-sign --armor --output "${ASC_FILE}.co" "${TARBALL}"
    cat "${ASC_FILE}.co" >> "${ASC_FILE}"
    rm  "${ASC_FILE}.co"
fi

# ---- 5. Verify before upload ----
#
# A release manager laptop glitch that produces a bad signature and
# ships uncaught is the kind of ceremonial failure that takes a
# project-wide day to unwind. Always re-verify.
gpg --verify "${SIG_FILE}" "${TARBALL}"
gpg --verify "${ASC_FILE}" "${TARBALL}"
gpg --verify "${SHA256_FILE}.asc"
sha256sum --check "${SHA256_FILE}"

# ---- 6. Upload to mirror network ----
#
# rsync push to the project's upstream mirror (ftp.gnu.org,
# mirrors.kernel.org, dist.apache.org/repos/dist/release/<proj>).
rsync -aH "${TARBALL}" "${SIG_FILE}" "${ASC_FILE}" \
      "${SHA256_FILE}" "${SHA256_FILE}.asc" \
      "rsync://uploads.${PROJECT}.example.org/release/${VERSION}/"

# Breakage:
#
# Every GNU project, kernel.org stable tarball, and ASF release since
# the mid-2000s is authenticated by this exact path. An RSA factoring
# attack on any of a few dozen RM keys lets an attacker:
#   - Substitute a malicious tarball that verifies under the
#     legitimate detached signature, and
#   - Push it to a CDN mirror (mirrors are rsync-pull from the
#     upstream, and the upload credential is separately managed —
#     but `gpg --verify` is the only check most downstream builders
#     perform).
# This is a supply-chain single point of failure for most of the Unix
# world.
