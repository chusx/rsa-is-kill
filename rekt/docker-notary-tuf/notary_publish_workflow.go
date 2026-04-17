// notary_publish_workflow.go
//
// Docker Content Trust / Notary publish pipeline — what `docker trust
// sign IMAGE` invokes under the hood, and the server-side path where
// TUF metadata lands on a Notary v1 server.
//
// Notary v1 + TUF remain the signing layer for Docker Official Images,
// every DTR / Mirantis MSR registry deployment, and a long tail of
// private registries still on the pre-Notary-v2 model. The RSA signing
// primitives are in `notary_rsa_root.go`; this file shows the
// role-graph orchestration (root / targets / snapshot / timestamp)
// that those primitives support.

package main

import (
	"context"
	"fmt"

	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/trustpinning"
	"github.com/theupdateframework/notary/tuf/data"
)

// PublishImageSignature runs the TUF four-role update any time a
// publisher pushes a new image tag.
//
// Role key material:
//
//	root       RSA-4096, offline / YubiHSM / Yubikey (touch required)
//	targets    RSA-2048, owned by the publishing team
//	snapshot   RSA-2048, held by Notary server (delegated)
//	timestamp  RSA-2048, held by Notary server, rotated frequently
func PublishImageSignature(ctx context.Context,
	gun data.GUN, // globally-unique repo name, e.g. "docker.io/library/nginx"
	tag string,
	manifestDigest []byte,
	manifestSize int64,
	trustDir string,
	notaryServer string,
) error {
	repo, err := client.NewFileCachedRepository(
		trustDir,
		gun,
		notaryServer,
		newAuthTransport(notaryServer),
		retrieveRootPassphrase, // prompts for Yubikey touch
		trustpinning.TrustPinConfig{},
	)
	if err != nil {
		return fmt.Errorf("open trust repo: %w", err)
	}

	// First-time publish: bootstrap all four role keys. Root key is
	// generated on a hardware token; the other three are Notary-local
	// and replicable.
	if _, err := repo.ListTargets(); err != nil {
		rootKey, err := repo.GetCryptoService().Create(
			data.CanonicalRootRole, gun, data.RSAKey)
		if err != nil {
			return err
		}
		if err := repo.Initialize([]string{rootKey.ID()}); err != nil {
			return err
		}
	}

	// Stage the new target.  TUF targets metadata enumerates every
	// signed tag in the repo with the manifest digest + size.
	target := &client.Target{
		Name:   tag,
		Hashes: data.Hashes{"sha256": manifestDigest},
		Length: manifestSize,
	}
	if err := repo.AddTarget(target, data.CanonicalTargetsRole); err != nil {
		return err
	}

	// Publish: Notary client signs targets.json under the targets RSA
	// key, pushes the change, Notary server counter-signs snapshot.json
	// and timestamp.json under its own RSA keys, and writes the
	// consistent-snapshot metadata set behind `gun`.
	if err := repo.Publish(); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// ---- Consumer side: `docker pull` resolves tag → digest through TUF ----
//
// Every daemon with `DOCKER_CONTENT_TRUST=1` (and every MSR cluster with
// image signing enforced) refuses to pull a tag that does not appear,
// with the expected digest, in a valid Targets role signed by a chain
// rooted at the pinned root RSA key.
//
// A factoring break on either the publisher's root key or (worse) the
// Docker Hub Library root lets an attacker:
//   - Substitute malicious `library/alpine`, `library/nginx`,
//     `library/postgres` at the digest level, with a signature that
//     every hardened Docker client accepts
//   - Push timestamped metadata that rolls back a well-known good
//     image to an earlier vulnerable digest without freshness alarms
//
// The Library root is one of the single most consequential RSA keys
// in the public software supply chain.

func newAuthTransport(_ string) interface{}          { return nil }
func retrieveRootPassphrase(_, _ string, _ bool, _ int) (string, bool, error) {
	return "", false, nil
}
