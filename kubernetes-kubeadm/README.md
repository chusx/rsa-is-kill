# Kubernetes kubeadm — RSA-2048 CA Certificates

**Source:** https://github.com/kubernetes/kubernetes  
**File:** `cmd/kubeadm/app/util/pkiutil/pki_helpers.go`  
**License:** Apache-2.0

## what it does

`kubeadm init` bootstraps a Kubernetes cluster by generating all required PKI material. `GeneratePrivateKey()` is the single function used for every CA and leaf certificate. The empty algorithm type — what you get when you run `kubeadm init` with no special flags, which is essentially everyone — maps to RSA-2048.

## impact

kubeadm creates RSA-2048 cluster CAs with 10-year validity. a cluster bootstrapped in 2025 has certs expiring in 2035. that window overlaps pretty uncomfortably with CRQC timelines.

- the CA signs everything: etcd certs, apiserver certs, kubelet client certs, front-proxy certs. forge any of those and you have full cluster control
- rsaKeySizeFromAlgorithmType("") returns 2048. the empty-string default is load-bearing. millions of production clusters were bootstrapped without specifying an algorithm and silently got RSA-2048
- Kubernetes 1.33 added hybrid ML-KEM key exchange for TLS (good). certificate signature validation is still RSA (the part that actually proves identity). partial win
- full PQC cert chain needs Go 1.26 ML-DSA support, plus updates to kube-apiserver, etcd, and kubelet. none of it is done yet
## migration status

Kubernetes 1.33 added hybrid key exchange. Certificate signature PQC is blocked on Go 1.26 ML-DSA. No timeline for full CA migration.
