# onnx-model-signing — RSA in ONNX model provenance for MLOps

**Standard:** ONNX (Open Neural Network Exchange) model format; ONNX Model Hub; ONNX Runtime
**Industry:** Cross-framework ML deployment, edge AI (mobile/embedded), browser inference (ONNX Runtime Web), enterprise MLOps
**Algorithm:** RSA-2048/3072/4096 (signing keys), SHA-256/384 digest, X.509 PKI

## What it does

ONNX is the lingua franca format for trained ML models moving between
training frameworks (PyTorch, TensorFlow, JAX) and inference runtimes
(ONNX Runtime, TensorRT, OpenVINO, CoreML, NNAPI, Windows ML, DirectML).
Nearly every deployed edge or browser AI model is converted to ONNX at
some point in its lifecycle.

ONNX models are protobuf files. For integrity / authenticity, several
overlapping signing approaches are in production use:

1. **Embedded metadata signature** — an `onnx.ModelProto.metadata_props`
   entry carrying a PKCS#7 or detached RSA signature over the model's
   canonical protobuf serialization.
2. **Azure ML Model Registry signing** — Microsoft signs every ONNX
   model registered in Azure ML with an RSA-2048 Microsoft CA chain;
   ONNX Runtime on Windows ML validates the chain before loading.
3. **Apple CoreML conversion signing** — when ONNX is converted to
   CoreML for iOS/macOS deployment, Apple's coremltools pipeline adds
   RSA-signed provenance that Xcode validates.
4. **Windows ML model catalog** — Windows Update-distributed system AI
   models (text-to-speech, OCR, Windows Studio Effects background blur,
   Copilot+ PC NPU models) are ONNX files signed with Microsoft's RSA
   code-signing chain and verified by the kernel-space ONNX Runtime
   before loading onto the NPU.
5. **ONNX Model Hub** — community + enterprise model repos apply
   `cosign` / Sigstore signatures (see `sigstore-model-signing/`).
6. **On-device classifiers on Android** — Google's AICore and Gemini
   Nano deployment pipeline ships ONNX/TFLite hybrids signed via the
   Google Play code-signing CA (RSA-2048).

The common thread: before an ONNX model is loaded onto an NPU, GPU, or
CPU inference runtime, a pipeline step validates a chain terminating
in an RSA trust anchor — Microsoft's code-signing root, Apple's
developer root, Google Play's signing root, or an enterprise CA.

## Why it's stuck

- ONNX Runtime's integration points (Windows ML, CoreML shim, Android
  NNAPI EP) trust the platform code-signing roots, which are RSA-
  dominated (Microsoft Root, Apple Root, Google Play root all RSA).
- Copilot+ PCs (Qualcomm X Elite, Intel Lunar Lake, AMD Ryzen AI)
  ship with Windows NPU-executed models loaded through Windows ML and
  gated on Microsoft-signed ONNX artifacts. The installed base of
  Copilot+ PCs grows with every OEM quarter; signed models deployed
  today must verify for the 5-8 year machine life.
- Edge AI deployments in factories, retail, and automotive load ONNX
  models at boot via an RSA-signed manifest; rotation requires
  physical or OTA updates to every device.
- On-device Gemini Nano on Pixel and Samsung + Android AICore ships
  signed ONNX/TFLite artifacts distributed via Play Protect, which is
  pinned to Google's RSA Play Developer signing CA.

## impact

- **Windows ML / Copilot+ PC backdooring**: Forge a Microsoft Windows
  ML signing cert → distribute malicious ONNX model to Copilot+ PCs
  as a signed Windows Update. The NPU runs the attacker's code as
  part of OCR, background blur, Studio Effects, or Copilot Recall.
  Kernel-level confidence in the model because it passed signed-model
  policy.
- **Mobile AI feature takeover**: Gemini Nano and iOS Foundation
  Models update channels distribute signed ONNX/CoreML artifacts.
  Forged signatures push misbehaving on-device LLMs to hundreds of
  millions of phones — output manipulation, data exfiltration,
  wake-word misfires.
- **Automotive perception poisoning**: In-vehicle neural accelerators
  (NVIDIA DRIVE, Mobileye EyeQ, Qualcomm Ride) load ONNX perception
  models verified against OEM-specific RSA signing roots. A forged
  signature means attacker-supplied perception behavior (misclassify
  stop signs, ignore pedestrians) with apparent authenticity.
- **Enterprise MLOps substitution**: Azure ML Model Registry, Google
  Vertex AI Model Registry, AWS SageMaker Model Registry all accept
  externally-signed ONNX uploads and track the signature in audit
  logs. Forge the signature → unauthorized model in production
  looking like a compliance-approved release.
- **Browser ONNX Runtime Web**: Web apps pulling ONNX from a CDN can
  verify a published signature to defeat CDN tampering; forging the
  signing key (often an RSA-2048 code-signing key) substitutes an
  adversarial model in-browser, affecting JS/WASM inference for
  every user of that app.

## Code

- `sign_onnx.py` — producer-side: canonicalize ONNX protobuf, compute
  SHA-384, sign with RSA-PSS, embed signature in `metadata_props` +
  emit a companion `model.sig` file.
- `verify_onnx.py` — consumer-side: extract signature, verify RSA
  chain, canonicalize and re-hash; returns success/failure and the
  validated signer subject.
- `winml_manifest.xml` — example Windows ML model catalog manifest
  listing ONNX models with their RSA-signed digests for NPU dispatch.
