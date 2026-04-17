// maa_policy.rego
//
// Example Microsoft Azure Attestation policy for a confidential AI VM
// running TDX. The policy is stored on the MAA attestation provider and
// evaluated server-side during the attest call; its output shapes the
// custom claims injected into the RS256 JWT that MAA returns.
//
// Uploaded to MAA via `az attestation policy set --attestation-type TDX`
// or via the ARM/REST API. Policy DSL is Rego-inspired but MAA uses its
// own evaluator; syntax shown here is illustrative.

version = 1.0;

authorizationrules
{
    c:[type=="x-ms-tdx-vm-is-debuggable"] => deny();
    c:[type=="x-ms-compliance-status", value=="azure-compliant-cvm"] => permit();
};

issuancerules
{
    // Copy standard TDX report fields into the issued token
    c:[type=="x-ms-tdx-mrtd"] => issue(type="x-ms-tdx-mrtd", value=c.value);
    c:[type=="x-ms-tdx-rtmr0"] => issue(type="x-ms-tdx-rtmr0", value=c.value);
    c:[type=="x-ms-tdx-rtmr1"] => issue(type="x-ms-tdx-rtmr1", value=c.value);
    c:[type=="x-ms-tdx-rtmr2"] => issue(type="x-ms-tdx-rtmr2", value=c.value);
    c:[type=="x-ms-tdx-rtmr3"] => issue(type="x-ms-tdx-rtmr3", value=c.value);

    // Custom policy-derived claim — identifies the model workload
    c:[type=="x-ms-tdx-mrtd",
       value=="3f8a2b1e4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef01"]
        => issue(type="x-ms-attested-ai-workload",
                 value="openai-gpt-image-serving-v3");

    // Gate on GPU co-attestation (NVIDIA NRAS result)
    c:[type=="x-ms-nvidia-nras-ccmode", value=="ON"] &&
    c:[type=="x-ms-nvidia-nras-measres", value=="success"]
        => issue(type="x-ms-co-attested-gpu-ok", value="true");

    // Runtime data claims — binds customer-supplied data (ephemeral key,
    // instance ID, operator identity) into the signed token
    c:[type=="x-ms-runtime"] => issue(type="x-ms-runtime", value=c.value);
};
