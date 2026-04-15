# docker-notary-tuf — RSA root keys in Docker Notary / TUF container signing

**Repository:** theupdateframework/notary, theupdateframework/go-tuf  
**Industry:** Container supply chain — Docker Hub, AWS ECR, Quay.io, enterprise Kubernetes  
**Algorithm:** RSA-4096 (TUF root key, Notary default); RSA-2048 (targets/snapshot keys)  
**PQC migration plan:** None — go-tuf and Notary have no PQC key types; TUF specification does not define ML-DSA algorithm IDs; no go-tuf roadmap item for post-quantum

## What it does

Docker Content Trust (DCT) uses Notary, which implements TUF (The Update Framework), to
sign container images. The TUF root key (RSA-4096 per Notary defaults) signs the root
metadata which in turn vouches for the targets key (RSA-2048) which signs actual image
manifests. The full public key chain is in `root.json` on the Notary server, downloadable
by any Docker client.

The root.json metadata file contains all four TUF public keys (root, targets, snapshot,
timestamp) in PEM format. This file is served over HTTPS and is not secret — it's the
basis for trust verification. Anyone who fetches it has the CRQC input for RSA-4096 and
RSA-2048 factoring.

Deployed in:
- Docker Hub official images (`library/*` — nginx, postgres, redis, python, node, etc.)
- AWS ECR with image signing enabled
- Quay.io and Red Hat container registry
- Any Kubernetes deployment with `DOCKER_CONTENT_TRUST=1`
- Portainer, Rancher enterprise deployments with DCT

Local key storage: `~/.docker/trust/private/*.key` — passphrase-encrypted PEM files,
often with weak or empty passphrases, often backed up with Docker configs.

## Why it's stuck

- go-tuf implements the TUF spec. The TUF specification (theupdateframework/specification)
  defines `rsa`, `ecdsa`, and `ed25519` key types. There is no `ml-dsa` key type in the spec.
  Adding one requires a TUF spec update and all Notary/go-tuf implementations updating.
- Docker Content Trust is rarely enabled in practice (most `docker pull` does not use DCT).
  Infrastructure for migrating keys is basically nonexistent because the feature is barely used.
- The root key is supposed to be stored offline. Rotating it requires bringing it online,
  re-signing root.json, and distributing the update. For large deployments, this is an
  orchestrated operation.

## impact

container image signing is the supply chain defense for Kubernetes. the TUF root key
is what makes signed images trustworthy.

- download root.json from the Notary server for docker.io (it's public). factor the
  RSA-4096 root key. now you can sign arbitrary root.json metadata delegating trust to
  your own targets key. sign new targets.json pointing to malicious image digests.
  any client doing `docker pull` with DCT will accept your signed images as official.
- for Docker Hub official images: `library/nginx`, `library/postgres`, `library/redis` —
  these are used as base images in millions of Dockerfiles. poisoned official images
  signed with forged TUF keys would propagate to every `docker build` that uses them.
- Kubernetes: pods with `imagePullPolicy: Always` and DCT enabled would pull and
  run the malicious images. DCT is the "supply chain security" story for these deployments.
- the offline root key story: "keep the root key offline and it's safe." the public key
  is in root.json on the server. public key factoring doesn't care whether the private key
  is on an air-gapped machine. the public key is the input, the private key is the output.
  "offline" is irrelevant against Shor's algorithm.

## Code

`notary_rsa_root.go` — `GenerateRSARootKey()` (RSA-4096, Notary default), `SignTUFMetadata()`
(RSASSA-PKCS1-v1_5 / SHA-256 over canonical JSON metadata), `VerifyTUFSignature()` (RSA verify),
`BuildRootMetadata()` (root.json with RSA-4096/RSA-2048 public keys — the CRQC input file).
Docker trust store key paths and DCT deployment context.
