package policy

# KBS Resource Policy — Rego
#
# Loaded into Trustee KBS at deploy time. Evaluated for every
# GET /resource call against the claims from the Attestation Service
# token (RS256 RSA-2048 signed by AS). Positive decision releases the
# requested resource; negative returns 403.
#
# This policy gates an AI model weight encryption key: release only to
# pods attested as TDX + running an approved container image + on an
# approved cluster + operator identity matches.

default allow = false

# Resource: openai/whisper-large-v3 decryption key
allow {
    input.resource_path == "openai/whisper-large-v3/key-v1"

    # Attestation must be Intel TDX
    input.claims["x-ms-attestation-type"] == "tdxvm"

    # Platform TCB must be at or above policy minimum
    input.claims["x-ms-tdx-tcb-svn-min-met"] == true

    # MRTD must match one of the approved container image measurements
    input.claims["x-ms-tdx-mrtd"] == approved_mrtd[_]

    # Running on an approved cluster (tenant isolation)
    input.claims["kubernetes.io/cluster-id"] == "coreweave-cc-prod-a1"

    # Operator identity (the K8s serviceaccount running the pod)
    input.claims["kubernetes.io/serviceaccount/namespace"] == "openai-whisper"

    # If the pod needs GPU weights, require NVIDIA co-attestation
    nvidia_attested_if_gpu
}

approved_mrtd := [
    "3f8a2b1e4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef01",
    # next approved image after rotation
    "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789aabcdef0123456789abcdef0123456789a",
]

nvidia_attested_if_gpu {
    not input.claims["kubernetes.io/nvidia-gpu-count"]
}

nvidia_attested_if_gpu {
    input.claims["kubernetes.io/nvidia-gpu-count"] > 0
    input.claims["x-nvidia-gpu-ccmode"] == "ON"
    input.claims["x-nvidia-gpu-driver-rim"] == "NVIDIA-H100-96.00.74.00.11"
}
