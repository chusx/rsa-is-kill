# Kubernetes kubeadm — RSA-2048 CA Certificates

**Source:** https://github.com/kubernetes/kubernetes  
**File:** `cmd/kubeadm/app/util/pkiutil/pki_helpers.go`  
**License:** Apache-2.0

## what it does

`kubeadm init` bootstraps a Kubernetes cluster by generating all required PKI material. `GeneratePrivateKey()` is the single function used for every CA and leaf certificate. The empty algorithm type — what you get when you run `kubeadm init` with no special flags, which is essentially everyone — maps to RSA-2048.

## why it's broken

- Every kubeadm-bootstrapped cluster has an RSA-2048 cluster CA with **10-year validity**. A cluster created in 2025 has certs expiring in 2035 — right in the window where CRQCs may exist.
- The CA signs etcd server/client certs, the apiserver cert, kubelet client certs, and the front-proxy cert. Forging any of these gives full cluster control.
- `rsaKeySizeFromAlgorithmType("") → 2048` — the empty-string default is load-bearing. Millions of clusters in production were bootstrapped without specifying an algorithm.
- PQC signatures require Go stdlib ML-DSA support (targeted for Go 1.26, ~late 2026) AND updates to `x/crypto/x509`, `kube-apiserver`, `etcd`, and `kubelet` to validate ML-DSA certs. The full chain is not ready.
- Kubernetes 1.33+ supports hybrid ML-KEM key exchange in TLS (so session keys are PQC-protected) but *authentication* — cert signatures — remains RSA. This is a partial mitigation only.

## migration status

Kubernetes 1.33 added hybrid key exchange. Certificate signature PQC is blocked on Go 1.26 ML-DSA. No timeline for full CA migration.
