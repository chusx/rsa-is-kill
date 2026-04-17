# huggingface-commit-signing — RSA in the ML model distribution hub

**Standard:** Git signed commits (GPG), Hugging Face Hub commit-signing extension
**Industry:** ML model distribution, open-weights foundation models, dataset hosting
**Algorithm:** RSA-2048/3072/4096 (OpenPGP commit signing keys), Ed25519 permitted but rare

## What it does

Hugging Face Hub hosts nearly every open-weights LLM, vision model, tokenizer,
and evaluation dataset in the industry: Llama, Mistral, Qwen, DeepSeek,
Stable Diffusion, Gemma, Phi, OLMo, Whisper, CLIP, and tens of thousands more.
Each model/dataset repository is a git repo backed by LFS.

Hugging Face implements **commit signing** using OpenPGP (GPG) — organizations
and individual researchers sign every commit that publishes or updates a
model repo. The "verified" badge on a Hugging Face repo page means the Hub
validated a GPG signature on the commit against a registered pubkey for the
author.

Integration points:

- **Hugging Face Hub commit verification** — pubkeys registered per user
  and per org; Hub validates signatures on every push
- **`huggingface_hub` Python client** — `snapshot_download(..., verify=True)`
  checks commit signatures before returning weights
- **Kaggle** mirrors HF models with preserved signatures
- **LangChain / LlamaIndex** ecosystem pulls HF snapshots into RAG pipelines
- **Enterprise on-prem HF deployments** (HF's Inference Endpoints, dedicated
  clusters) verify signatures before loading weights into production
- **EleutherAI, BigScience, AI2, Nous Research** consortium release workflows
  center on signed HF commits

GPG keys in wide use across the HF community are predominantly RSA (RSA-2048,
RSA-3072, RSA-4096) because legacy `gpg --gen-key` defaults and GitHub's
commit-signing UX trained users into RSA. Ed25519 GPG keys are supported but
uncommon.

## Why it's stuck

- The commit-signing pubkey ring is organic — maintainers register whatever
  keys they have, usually RSA. Top-100 HF organizations (Meta, Mistral AI,
  Stability AI, Cohere, BAAI, Alibaba) publish RSA-4096 keys on their GitHub
  profiles; the same keys end up as HF verified keys.
- Published key material is globally accessible (`https://github.com/USER.gpg`,
  HF org pages, keyservers). Any would-be attacker can harvest all RSA pubkeys
  of interest instantly.
- Historical commits are signed once; the signature lives forever in the
  repo. Even if an org rotates to Ed25519, old weights still verify against
  old RSA keys, which is what model archaeologists / auditors check years
  later.
- Hugging Face does not currently offer hardware-attestation-backed signing
  for model releases; the trust model is "commit signature under a pubkey
  we've seen before."

## impact

- **Poisoned foundation model distribution**: Forge an RSA-signed commit
  under `meta-llama` or `mistralai` pushing a new weight revision with
  an embedded backdoor trigger (e.g., sleeper-agent behavior on specific
  inputs). Downstream: Ollama, vLLM, HF Inference Endpoints, LangChain
  RAG stacks, and millions of developers consume the "verified" weights.
- **Retroactive provenance rewriting**: Re-sign historical commits of a
  controversial dataset (e.g., LAION, The Pile variants) to alter which
  docs were included, escaping copyright or content-safety audits.
- **Fine-tune supply-chain poisoning**: Enterprise fine-tuning pipelines
  trust a base-model SHA against a signed commit. Forge the signature →
  deploy a poisoned base while appearing to use the genuine release.
- **Research integrity collapse**: Reproducibility in AI research
  increasingly depends on pinning HF model revisions. Signatures are the
  only defense against silent weight substitution. Break them and
  reproducibility claims become unverifiable.
- **Hugging Face Spaces / Datasets**: Same signing mechanism covers
  Spaces apps (interactive ML demos) and datasets used for alignment /
  RLHF. Compromise the signer of a benchmark like `lmsys/chatbot-arena`
  or a safety eval dataset and research outcomes shift.

## Code

- `hf_commit_verify.py` — HF Hub-side: walk a model's commits, verify
  OpenPGP RSA signatures against the org's registered pubkey ring.
- `hf_signed_push.py` — client-side: sign a commit with GPG RSA before
  pushing model weights to HF Hub.
- `org_keyring.asc` — example OpenPGP keyring layout showing RSA-4096
  org keys as they appear in HF's verified-author configuration.
