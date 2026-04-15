# Git commit-signing policy — engineering ops

This is the rolled-up policy that sits behind the RSA signing helper
in `git_rsa_signing.sh`. Captures what Fortune 500 engineering orgs
actually enforce when they require signed commits — and what GitHub,
GitLab, Bitbucket Server, and Gerrit do with the resulting signatures
on the server side.

## When signatures are required

| Scope                                    | Signing requirement                       |
|------------------------------------------|-------------------------------------------|
| `main`, `release/*`, `hotfix/*`          | **Required** — protected-branch rule      |
| Tags on releases shipped to customers    | **Required** — `git tag -s`               |
| Personal working branches                | Optional                                  |
| Dependabot / Renovate automated PRs      | Signed by bot RSA key in HSM              |
| CI-generated merge commits               | Signed by the merge-queue service account |

## Key issuance

- Per-user RSA-4096 OpenPGP keys, on-card (YubiKey 5 or Nitrokey 3).
  Touch required per signature.
- Corporate keyring published via the SKS-successor Hagrid instance at
  `keys.corp.example.com`; also uploaded to `keys.openpgp.org`.
- Expiry 2 years, extended via rotation script at 6-months-remaining.
- Revocation certs escrowed with the Security Engineering team in the
  physical safe (printed + sealed).

## Server-side enforcement

- **GitHub Enterprise**: protected-branch rule `Require signed commits`.
  GitHub re-verifies the signature against the committer's uploaded
  public key on every push. "Verified" badge renders in PR UI.
- **Gerrit**: `receive.requireSignedPush = true`; gerrit-verify hook
  walks the trust DB before accepting a ref update.
- **Bitbucket Server**: same, via the `com.atlassian.bitbucket.server.
  signed-commits` plugin.

Pipelines refuse to promote an artifact built from an unsigned merge
commit on `main`. This gates production release.

## `commit.gpgsign` + wrap

Every dev box has:

```
git config --global commit.gpgsign     true
git config --global tag.gpgsign        true
git config --global user.signingkey    0xA1B2C3D4E5F6DEADBEEF
git config --global gpg.program        /usr/bin/gpg2
```

YubiKey PIN is unlocked via `gpg-agent` + `pinentry-gnome3`; the card
enforces the 3-strike lockout.

## Relationship to the RSA crypto

Every commit/tag signature is RSA-PKCS#1 v1.5 + SHA-512 produced by
the on-card keypair.  Git's `--verify-commit` and `--verify-tag`
subcommands (plus `git log --show-signature`) call out to `gpg2
--verify` which runs the signature through GnuPG's libgcrypt RSA
implementation. That path is `git_rsa_signing.sh` in this directory.

## Failure modes

- **Key-on-laptop leakage**: a stolen unencrypted keyring is game-over;
  the on-card policy above is specifically to prevent this.
- **Factoring attack on RSA**: every commit and tag signature in the
  repository history becomes forgeable. Attackers can rewrite history
  (where branch protection allows force-push), or push new commits
  under any developer's identity. The "Verified" badge becomes
  meaningless org-wide.
- Downstream SLSA provenance attestations often include a reference
  to the commit signature — so a factoring break silently invalidates
  the supply-chain story the organization tells its customers.

## Migration plan (once a post-RSA primitive is trusted)

1. Generate per-user Ed25519 OpenPGP keys alongside RSA keys;
   cross-sign both under corporate HR identity attestations.
2. Flip server-side enforcement to require at least one non-RSA
   signature on every protected-branch commit.
3. Retire RSA commit-signing keys after a full release train has
   moved.
