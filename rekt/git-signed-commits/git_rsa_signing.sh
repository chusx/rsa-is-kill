#!/bin/bash
# git_rsa_signing.sh
#
# Git commit/tag signing — RSA-2048/4096 GPG signatures (Linux kernel, etc.)
# Sources:
#   - git-commit(1), git-tag(1), git-verify-commit(1)
#   - Linux kernel signing key policy: https://www.kernel.org/category/releases.html
#   - https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
#
# Git supports GPG signing of commits and tags.
# The Linux kernel uses RSA-2048 GPG keys for release tag signing.
# Linus Torvalds' signing key: RSA-2048
# Greg Kroah-Hartman's signing key: RSA-4096
#
# Linux kernel release signing keys (from kernel.org):
#   Linus Torvalds:
#     pub   rsa2048 2011-09-20 [SC]
#     Key: ABAF 11C6 5A29 70B1 30AB  E3C4 79BE 3E43 0041 1886
#
#   Greg Kroah-Hartman (stable releases):
#     pub   rsa4096 2011-09-23 [SC]
#     Key: 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6093 2294
#
# Additionally, many development teams sign commits:
#   - GitHub "Verified" badge for signed commits (GPG or SSH)
#   - GitLab commit verification
#   - Sigstore / Gitsign uses OIDC-based signing (but many still use GPG RSA)
#
# When you do `git tag -s v6.12` or `git commit -S`, git calls GnuPG to sign
# the commit/tag object hash. The signature is stored in the git object.
# Verification: `git verify-tag v6.12` or `git verify-commit HEAD`

set -euo pipefail

# Linux kernel signing key IDs
LINUS_KEY_ID="79BE3E4300411886"       # Linus Torvalds RSA-2048
GREG_KEY_ID="38DBBDC86093229"         # Greg Kroah-Hartman RSA-4096

# =============================================================================
# show_kernel_signing_keys() — display RSA signing keys used by kernel maintainers
# =============================================================================
show_kernel_signing_keys() {
    echo "[*] Linux kernel release signing keys:"
    echo ""

    # Kernel.org publishes all maintainer keys
    # These are RSA-2048 and RSA-4096 GPG keys
    gpg --keyserver hkps://keys.openpgp.org \
        --recv-keys 79BE3E4300411886 2>/dev/null || true
    gpg --list-keys 79BE3E4300411886 2>/dev/null | head -8

    echo ""
    gpg --keyserver hkps://keys.openpgp.org \
        --recv-keys 38DBBDC86093229 2>/dev/null || true
    gpg --list-keys 38DBBDC86093229 2>/dev/null | head -8
}

# =============================================================================
# git_verify_kernel_tag() — verify RSA signature on a Linux kernel release tag
# =============================================================================
git_verify_kernel_tag() {
    local tag="${1:-v6.12}"
    local kernel_repo="${2:-/usr/src/linux}"

    echo "[*] Verifying kernel release tag: $tag"

    if [[ ! -d "$kernel_repo" ]]; then
        echo "[-] Kernel repo not found at $kernel_repo"
        return 1
    fi

    cd "$kernel_repo"

    # git verify-tag calls GnuPG, which calls libgcrypt/OpenSSL for RSA verify
    # The tag object contains the signed content + detached RSA signature
    git verify-tag "$tag" 2>&1
    # Good signature from "Linus Torvalds <torvalds@linux-foundation.org>"
    # RSA key ID: 79BE3E4300411886
}

# =============================================================================
# git_sign_commit() — sign a git commit with GPG RSA key
# =============================================================================
git_sign_commit() {
    local key_id="${1:-$LINUS_KEY_ID}"
    local message="${2:-signed commit}"

    echo "[*] Signing commit with key: $key_id"

    # -S = use GPG signing; calls gpg --sign with the configured key
    # GPG internally calls libgcrypt for RSA-2048 PKCS#1 v1.5 sign
    GIT_COMMITTER_EMAIL="user@example.com" \
    git commit -S --gpg-sign="$key_id" -m "$message" --allow-empty

    echo "[+] Commit signed with RSA key: $key_id"
}

# =============================================================================
# git_sign_tag() — sign a git release tag (kernel release style)
# =============================================================================
git_sign_tag() {
    local tag_name="${1:-v1.0.0}"
    local tag_message="${2:-Release $1}"
    local key_id="${3:-$LINUS_KEY_ID}"

    echo "[*] Signing release tag: $tag_name"
    echo "[*] Key: $key_id"

    # -s = signed tag; calls GnuPG RSA signing
    # The signed content is: "tag <name>\ntype commit\ntagger <identity>\n\n<message>"
    # This hash is what the RSA key signs
    git tag -s "$tag_name" -m "$tag_message" -u "$key_id"

    echo "[+] Tag created: $tag_name"
    git verify-tag "$tag_name"
}

# =============================================================================
# show_commit_signature() — display RSA signature stored in a git commit
# =============================================================================
show_commit_signature() {
    local commit="${1:-HEAD}"

    echo "[*] Commit signature for: $commit"

    # git cat-file shows the raw commit object including the PGP signature
    git cat-file commit "$commit" | sed -n '/^gpgsig/,/^-----END PGP SIGNATURE-----/p'

    echo ""
    echo "[*] Verification:"
    git verify-commit "$commit" 2>&1 || true
    # Output includes: "RSA key ID <16 hex chars>"
}

# =============================================================================
# check_unsigned_kernel_commits() — find unsigned commits in kernel repo
# =============================================================================
check_unsigned_kernel_commits() {
    local since="${1:-v6.11}"
    local until="${2:-HEAD}"

    echo "[*] Checking for unsigned commits: $since..$until"
    echo "[*] (Kernel policy: merge commits must be signed by maintainer)"

    git log --format="%H %G? %GK %an: %s" "$since..$until" | \
        grep -E "^[a-f0-9]+ [NE] " | head -20
    # G? = good sig, B = bad sig, N = no sig, E = expired key, U = unknown
}

# ATTACK SCENARIO:
#
# Linux kernel release tags are signed with RSA-2048 (Linus) or RSA-4096 (Greg).
# The public keys are at kernel.org and on keyservers (hkps://keys.openpgp.org).
#
# `git verify-tag v6.12` verifies that the tag was signed by the maintainer's RSA key.
# Distributions (Debian, Ubuntu, Fedora, Arch) verify kernel tarball signatures
# before building kernel packages. This is the authenticity check for the kernel source.
#
# Factor Linus's RSA-2048 key. Sign a git tag on a modified kernel tree.
# The modification could be a backdoor in the kernel (drivers/net, fs/*, arch/x86/).
# The tag now shows "Good signature from Linus Torvalds" on git verify-tag.
#
# For this attack to matter, you'd also need to get the modified tree into the
# distribution's build pipeline — which requires more than just a valid GPG sig.
# But the valid GPG sig is the first gatekeeper, and it's the one that says
# "this came from the kernel maintainers."
#
# Practical higher-value target: enterprise Git repos using signed commits for
# compliance (SOC 2, ISO 27001). If the signing key is RSA-2048 and the auditor
# relies on GPG signature verification for code review accountability, forged
# signatures undermine the audit trail.
#
# GitHub's "Verified" badge appears on commits signed with any key in the
# committer's GitHub account (GPG or SSH key). If the committer's GPG key is
# RSA-2048, factor it, sign commits as that developer, push to a branch,
# get a "Verified" badge. This looks like the developer wrote the code.
