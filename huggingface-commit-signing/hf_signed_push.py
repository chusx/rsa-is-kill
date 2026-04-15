"""
hf_signed_push.py

Producer-side: sign and push a model update to Hugging Face Hub with a
GPG-signed commit. Typical flow used by model-release pipelines at
Meta, Mistral, Stability AI, Google DeepMind, Microsoft Research, etc.

Signing key is almost always an RSA-4096 OpenPGP key held either on:
  - A developer's YubiKey in OpenPGP smartcard mode (RSA-backed slot)
  - An HSM wrapping an RSA GPG subkey exported via gpg-agent
  - A dedicated release host's gpg keyring
"""

import os
import subprocess
from pathlib import Path
from huggingface_hub import HfApi, CommitOperationAdd


def prepare_signed_commit(repo_local_path: Path,
                            signing_key_id: str,
                            commit_message: str) -> str:
    """
    Stage weights, tokenizer, config; create a GPG-signed commit with
    the supplied key. Returns the commit SHA.
    """
    env = os.environ.copy()
    env["GIT_COMMITTER_NAME"] = os.environ.get("RELEASE_BOT_NAME",
                                                  "mistralai-release-bot")
    env["GIT_COMMITTER_EMAIL"] = os.environ.get("RELEASE_BOT_EMAIL",
                                                  "release@mistral.ai")

    subprocess.run(["git", "-C", str(repo_local_path), "add", "-A"],
                   check=True, env=env)
    subprocess.run(
        ["git", "-C", str(repo_local_path),
         "-c", f"user.signingkey={signing_key_id}",
         "commit",
         "-S",                       # sign with GPG
         "-m", commit_message],
        check=True, env=env,
    )

    sha = subprocess.check_output(
        ["git", "-C", str(repo_local_path), "rev-parse", "HEAD"]
    ).decode().strip()
    return sha


def push_to_hub(repo_local_path: Path,
                 repo_id: str,
                 token: str) -> None:
    """
    Push the signed commits to the HF Hub. Hub receives the full commit
    object including the `gpgsig` header and validates it server-side
    against the registered keys for the pushing user / org.
    """
    subprocess.run(
        ["git", "-C", str(repo_local_path), "push",
         f"https://{token}@huggingface.co/{repo_id}", "HEAD:main"],
        check=True,
    )


def release_model(repo_local_path: Path,
                   repo_id: str,
                   weight_files: list,
                   signing_key_id: str,
                   commit_message: str,
                   hf_token: str) -> str:
    """
    Complete release: stage weight files (safetensors shards, config,
    tokenizer), create GPG-RSA-signed commit, push. Returns commit SHA.
    """
    for src in weight_files:
        dst = repo_local_path / Path(src).name
        dst.write_bytes(Path(src).read_bytes())

    sha = prepare_signed_commit(
        repo_local_path, signing_key_id, commit_message)
    push_to_hub(repo_local_path, repo_id, hf_token)
    return sha


if __name__ == "__main__":
    # Typical invocation inside a model release CI run
    sha = release_model(
        repo_local_path=Path("/tmp/hf-model-workspace"),
        repo_id="mistralai/Mixtral-8x22B-v0.2",
        weight_files=[
            "/artifacts/model-00001-of-00056.safetensors",
            "/artifacts/model-00002-of-00056.safetensors",
            # ... all shards ...
            "/artifacts/config.json",
            "/artifacts/tokenizer.json",
        ],
        signing_key_id="mistralai-release@mistral.ai",
        commit_message="release: Mixtral-8x22B-v0.2 weights",
        hf_token=os.environ["HF_TOKEN"],
    )
    print(f"released commit: {sha}")
