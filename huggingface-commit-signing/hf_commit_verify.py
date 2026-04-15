"""
hf_commit_verify.py

Hub-side verification of OpenPGP commit signatures on Hugging Face
model/dataset repositories. Runs in:
  - Hugging Face Hub backend (attaches the "verified" badge)
  - `huggingface_hub` Python client (`verify_commit_signatures=True`)
  - Enterprise on-prem HF deployments (gating model deployment on
    successful signature verification)
  - CI systems that pin a model repo SHA + require a known-good signer

The signature is a standard git commit signature (OpenPGP detached over
the canonical commit object sans `gpgsig` header), predominantly RSA
because the long tail of HF contributors uses RSA GPG keys.
"""

import subprocess
import re
from pathlib import Path
from typing import Optional
import requests


HF_API = "https://huggingface.co/api"


class SignatureVerificationError(Exception):
    pass


def fetch_commit_data(repo_id: str, commit_sha: str,
                       repo_type: str = "model") -> bytes:
    """Pull raw git commit object bytes via HF API."""
    url = f"{HF_API}/{repo_type}s/{repo_id}/commits/{commit_sha}.git"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.content


def fetch_signer_keyring(author_email_or_org: str) -> bytes:
    """
    Pull the OpenPGP pubkey(s) HF has registered for an author or org.
    Returns concatenated ASCII-armored keys.
    """
    url = f"{HF_API}/users/{author_email_or_org}/gpg-keys"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text.encode()


def verify_pgp_signature(commit_object: bytes,
                          keyring_asc: bytes) -> dict:
    """
    Verify a git commit's PGP signature against the supplied keyring.
    Returns {"valid": bool, "key_id": str, "key_alg": str,
             "signer_uid": str}.
    Uses gpg in a temp dir for isolation.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        # Import pubkeys
        subprocess.run(
            ["gpg", "--homedir", str(home), "--import"],
            input=keyring_asc, check=True, capture_output=True,
        )

        # Split commit into content + embedded signature
        signed_data, signature = _split_git_commit(commit_object)

        sigfile = home / "commit.sig"
        sigfile.write_bytes(signature)
        datafile = home / "commit.data"
        datafile.write_bytes(signed_data)

        proc = subprocess.run(
            ["gpg", "--homedir", str(home), "--status-fd", "1",
             "--verify", str(sigfile), str(datafile)],
            capture_output=True,
        )
        status = proc.stdout.decode()

    return _parse_gpg_status(status)


def _split_git_commit(commit_object: bytes) -> tuple:
    """
    Extract gpgsig block and return (commit-without-gpgsig, signature).
    Git commits with signatures have a `gpgsig` header preceding the
    commit message; the signature itself is ASCII-armored PGP.
    """
    lines = commit_object.split(b"\n")
    out_lines = []
    sig_lines = []
    in_sig = False
    for line in lines:
        if line.startswith(b"gpgsig "):
            in_sig = True
            sig_lines.append(line[len(b"gpgsig "):])
        elif in_sig and line.startswith(b" "):
            sig_lines.append(line[1:])
        else:
            in_sig = False
            out_lines.append(line)
    return b"\n".join(out_lines), b"\n".join(sig_lines)


def _parse_gpg_status(status: str) -> dict:
    """Parse `gpg --status-fd 1` machine-readable output."""
    result = {"valid": False, "key_id": None, "key_alg": None,
              "signer_uid": None}
    for line in status.splitlines():
        if line.startswith("[GNUPG:] GOODSIG"):
            parts = line.split()
            result["key_id"] = parts[2]
            result["signer_uid"] = " ".join(parts[3:])
            result["valid"] = True
        if line.startswith("[GNUPG:] VALIDSIG"):
            parts = line.split()
            # parts[2] is signature creation date; parts[9] is key algo
            # (1 = RSA, 17 = DSA, 22 = EdDSA)
            if len(parts) > 9:
                result["key_alg"] = {1: "RSA", 17: "DSA",
                                     22: "EdDSA"}.get(int(parts[9]), parts[9])
    return result


def verify_repo_head(repo_id: str,
                      required_signer_org: Optional[str] = None,
                      repo_type: str = "model") -> dict:
    """
    Top-level: verify HEAD commit of a HF model/dataset repo. Returns
    verification record. Raises on any failure.
    """
    meta = requests.get(
        f"{HF_API}/{repo_type}s/{repo_id}", timeout=30).json()
    head_sha = meta["sha"]
    author = meta.get("author", required_signer_org)

    commit = fetch_commit_data(repo_id, head_sha, repo_type)
    keyring = fetch_signer_keyring(author)

    result = verify_pgp_signature(commit, keyring)
    if not result["valid"]:
        raise SignatureVerificationError(f"bad signature on {head_sha}")

    if required_signer_org and author != required_signer_org:
        raise SignatureVerificationError(
            f"signer {author} != required {required_signer_org}")

    return {
        "repo_id": repo_id,
        "head_sha": head_sha,
        "signer": author,
        "key_alg": result["key_alg"],
        "key_id": result["key_id"],
    }
