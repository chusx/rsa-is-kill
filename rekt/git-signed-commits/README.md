# git-signed-commits — RSA in git commit/tag signing (Linux kernel, GitHub Verified)

**Repository:** git (git-scm.com/git); Linux kernel signed releases (kernel.org) 
**Industry:** Open source software supply chain; enterprise code integrity 
**Algorithm:** RSA-2048 (Linus Torvalds signing key); RSA-4096 (Greg Kroah-Hartman stable key) 

## What it does

Git supports GPG-signed commits and tags. The Linux kernel uses this for release tags:
Linus signs tags on the main release tree with RSA-2048; Greg Kroah-Hartman signs stable
release tags with RSA-4096. The keys are on `keys.openpgp.org` and `keyserver.ubuntu.com`.

The signed content is the git object hash (commit or tag) — git calls GnuPG, GnuPG calls
libgcrypt for the RSA operation, the signature is stored as a `gpgsig` header in the git
object. `git verify-tag v6.12` checks this against the maintainer's public key.

Linux distributions (Debian, Ubuntu, Fedora, Arch, Gentoo) verify kernel tarball signatures
before building packages. This is the authenticity check in the kernel supply chain.

Beyond the kernel: GitHub shows a "Verified" badge on any commit signed with a key linked
to the committer's GitHub account. Millions of developers sign commits with GPG RSA-2048
keys (GitHub's GPG key generation docs use RSA as the first example). Many enterprise
repositories require signed commits for SOC 2 / ISO 27001 audit trails.

## Why it's stuck

- GnuPG ML-DSA support is experimental and not in stable releases. The key type
 doesn't even have a stable OpenPGP algorithm ID yet (the draft is in progress in IETF).
- Linus and Greg's signing keys are RSA-2048/4096 and have been in use for years.
 The fingerprints are hardcoded in distribution build scripts. Rotating them requires
 a coordinated announcement + distribution script updates.
- GitHub's GPG key upload accepts whatever key the user generates. Most users generate
 RSA-2048 following GitHub's own (now updated) instructions. Existing keys are not
 automatically rotated.

## impact

git signing is the audit trail for code — who wrote what, and is it really from them.
the RSA key is the cryptographic basis for "this code was approved by the Linux kernel maintainers."

- Linus's RSA-2048 public key is on the keyservers. factor it. sign a git tag
 for a modified kernel tree. `git verify-tag` reports: "Good signature from Linus Torvalds."
 this is the gate that distribution build scripts check. a forged tag with a valid RSA
 signature passes the check.
- GitHub "Verified" badge: if a developer's GPG signing key is RSA-2048, factor it, sign
 commits as them with their key ID. GitHub shows the green "Verified" badge. their employer
 sees commits from that developer that the developer never wrote. in a company where signed
 commits are the accountability mechanism for code review, this breaks the audit trail.
- signed git tags in CI/CD: many pipelines check `git verify-tag` before deploying a release.
 a forged release tag with a valid RSA signature triggers the deployment pipeline. this is
 the trigger for production deployments, automated rollouts, container builds.
- enterprise compliance: SOC 2 Type II, ISO 27001, and various banking compliance frameworks
 accept signed commits as evidence of code provenance. forged RSA signatures = forged
 evidence trail = audit artifacts that lie.

## Code

`git_rsa_signing.sh` — `show_kernel_signing_keys()` (kernel.org RSA-2048/RSA-4096 GPG keys),
`git_verify_kernel_tag()` (git verify-tag calling GnuPG RSA verify), `git_sign_commit()`
(git commit -S with RSA key), `git_sign_tag()` (git tag -s for release signing),
`show_commit_signature()` (gpgsig header from git cat-file). Linux kernel release signing
key fingerprints and supply chain attack scenario in comments.
