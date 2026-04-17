"""
tuf_target_verify.py

Docker Content Trust / Notary v1/v2 TUF (The Update Framework)
target verification. Docker Content Trust signs container image
digests with an RSA key (root, targets, snapshot, timestamp
roles). The root key is RSA-2048/4096 by default.

A factored root key allows an attacker to forge the entire TUF
metadata chain and convince `docker pull --disable-content-trust=false`
to accept a trojanized image.

Also applicable to: Notary v2 (ORAS signatures), cosign (Sigstore
when backed by RSA), TUF-based Python/Go/Ruby package managers.
"""

import hashlib
import json
import time
from dataclasses import dataclass


@dataclass
class TufRoot:
    """root.json — the trust anchor for a TUF repository.
    Signed by the root key(s); delegates to targets/snapshot/
    timestamp keys."""
    version: int
    expires: str
    keys: dict          # keyid -> {"keytype": "rsa", "keyval": {"public": "..."}}
    roles: dict         # "root"/"targets"/"snapshot"/"timestamp" -> {"keyids":[...], "threshold":1}
    signatures: list    # [{"keyid":"...", "sig":"RSA-SHA256 hex"}]


@dataclass
class TufTargets:
    """targets.json — lists every signed image digest."""
    version: int
    expires: str
    targets: dict       # "library/nginx:1.25" -> {"hashes":{"sha256":"..."}, "length":...}
    delegations: dict   # optional: delegate to per-repo keys
    signatures: list


def verify_root(root_json: bytes, trusted_root_pub: bytes) -> TufRoot:
    """Verify root.json signature against compiled-in root key."""
    root = json.loads(root_json)
    signed_bytes = canonical_json(root["signed"])
    for sig in root["signatures"]:
        if sig["keyid"] == key_fingerprint(trusted_root_pub):
            h = hashlib.sha256(signed_bytes).digest()
            if not rsa_verify_sha256(trusted_root_pub, h,
                                      bytes.fromhex(sig["sig"])):
                raise ValueError("root signature invalid")
            return TufRoot(**root["signed"])
    raise ValueError("no matching root signature")


def verify_targets(targets_json: bytes, root: TufRoot) -> TufTargets:
    """Verify targets.json signature against the targets key
    designated in root.json."""
    targets = json.loads(targets_json)
    targets_keyid = root.roles["targets"]["keyids"][0]
    targets_pub = root.keys[targets_keyid]["keyval"]["public"]
    signed_bytes = canonical_json(targets["signed"])
    for sig in targets["signatures"]:
        if sig["keyid"] == targets_keyid:
            h = hashlib.sha256(signed_bytes).digest()
            if not rsa_verify_sha256(targets_pub.encode(), h,
                                      bytes.fromhex(sig["sig"])):
                raise ValueError("targets sig invalid")
            return TufTargets(**targets["signed"])
    raise ValueError("no matching targets signature")


def docker_pull_verify(image_ref: str, digest: str,
                       trusted_root_pub: bytes):
    """Full Docker Content Trust verification path."""
    # 1. Fetch TUF metadata from Notary server.
    root_json = notary_fetch("root.json", image_ref)
    root = verify_root(root_json, trusted_root_pub)

    # 2. Timestamp -> snapshot -> targets chain.
    ts = verify_timestamp(notary_fetch("timestamp.json", image_ref), root)
    snap = verify_snapshot(notary_fetch("snapshot.json", image_ref), root, ts)
    targets = verify_targets(notary_fetch("targets.json", image_ref), root)

    # 3. Look up the image digest in targets.
    tag = image_ref.split(":")[-1] if ":" in image_ref else "latest"
    if tag not in targets.targets:
        raise ValueError(f"image {tag} not in signed targets")
    expected_digest = targets.targets[tag]["hashes"]["sha256"]
    if digest != expected_digest:
        raise ValueError("digest mismatch — image tampered")

    return True  # Image is trusted.


# ---- Stubs -------------------------------------------------------
def canonical_json(d): return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
def key_fingerprint(pub): ...
def rsa_verify_sha256(pub, h, sig): ...
def notary_fetch(role, ref): ...
def verify_timestamp(data, root): ...
def verify_snapshot(data, root, ts): ...


# ---- Attack path once root key is factored --------------------
#
# 1. Factor the root key (RSA-2048/4096) from root.json — which
#    is public metadata fetched by every `docker pull`.
# 2. Forge a new root.json delegating targets to attacker key.
# 3. Forge targets.json binding "library/nginx:1.25" to the
#    digest of a trojanized nginx image.
# 4. Host forged metadata on a MitM'd Notary server (or on a
#    registry that mirrors Docker Hub).
# 5. `docker pull --disable-content-trust=false library/nginx:1.25`
#    verifies the forged TUF chain and pulls the trojanized image.
#
# Blast: every CI/CD pipeline, every Kubernetes cluster, every
# Docker-based PaaS that enforces Content Trust. Container
# supply-chain attack at Docker Hub scale.
#
# Recovery: Docker / CNCF rotate Notary root keys; every
# consumer updates their trust anchor. The update mechanism
# (TUF root rotation) is itself validated by the broken key —
# partial bootstrap paradox mitigated by TUF's root rotation
# spec, but real-world consumers rarely monitor root changes.
