#!/bin/bash
# cluster_bootstrap.sh
#
# kubeadm-driven Kubernetes control-plane bootstrap. This is the exact
# sequence that brings a new cluster online with its full RSA-based PKI
# — everything the cluster will later use for authN/authZ between
# apiserver, kubelet, etcd, scheduler, controller-manager, and every
# workload doing in-cluster TLS.  The raw RSA keygen + cert issuance
# primitives live in `pki_helpers_rsa.go`.
#
# This is the bootstrap flow that runs on:
#   - Every self-hosted k8s cluster (on-prem bare metal, vSphere,
#     OpenStack, Nutanix)
#   - Hardened platforms: Red Hat OpenShift installer (via openshift-
#     install → cluster-kube-apiserver-operator, same cert shapes),
#     Rancher RKE2, Mirantis MKE, SUSE Rancher, Canonical Charmed k8s
#   - CNCF reference distros: k3s, k0s, kind, minikube (with --embed-certs)
#
# Managed k8s (EKS/AKS/GKE) uses a similar cert shape under the hood,
# just managed by the cloud provider.

set -euo pipefail

CLUSTER_NAME=${1:?cluster name}
CONTROL_PLANE_ENDPOINT=${2:?control-plane endpoint (e.g. k8s-api.corp.local:6443)}

# ---- 1. CA bundle generation ----
#
# kubeadm generates the following RSA-2048 CAs in /etc/kubernetes/pki:
#
#   ca.crt                   cluster-wide root (apiserver, kubelet client auth)
#   etcd/ca.crt              separate etcd root (peer + server + client)
#   front-proxy-ca.crt       aggregation-layer proxy root
#   sa.pub / sa.key          ServiceAccount token *signing* key (RSA-2048)
#
# The SA signing key is the one every in-cluster pod mounts as its
# projected service-account token; it ultimately authenticates
# workloads to the apiserver and to any RBAC-guarded in-cluster
# service. It is the highest-leverage key in the cluster.

kubeadm init phase certs ca          --cert-dir /etc/kubernetes/pki
kubeadm init phase certs etcd-ca     --cert-dir /etc/kubernetes/pki
kubeadm init phase certs front-proxy-ca --cert-dir /etc/kubernetes/pki
kubeadm init phase certs sa          --cert-dir /etc/kubernetes/pki

# ---- 2. Leaf certs under those CAs ----
#
# All RSA-2048, 365-day default validity, auto-renewed on
# `kubeadm certs renew all` at upgrade time.
kubeadm init phase certs apiserver \
    --control-plane-endpoint "${CONTROL_PLANE_ENDPOINT}" \
    --service-cidr 10.96.0.0/12
kubeadm init phase certs apiserver-kubelet-client
kubeadm init phase certs apiserver-etcd-client
kubeadm init phase certs front-proxy-client
kubeadm init phase certs etcd-server
kubeadm init phase certs etcd-peer
kubeadm init phase certs etcd-healthcheck-client

# ---- 3. Kubeconfigs ----
#
# Each kubeconfig embeds its subject's RSA client cert + matching CA
# bundle.  The admin kubeconfig is the one handed to cluster operators
# at bootstrap and is root-equivalent — possession == cluster-admin.
kubeadm init phase kubeconfig admin
kubeadm init phase kubeconfig super-admin
kubeadm init phase kubeconfig controller-manager
kubeadm init phase kubeconfig scheduler
kubeadm init phase kubeconfig kubelet

# ---- 4. Launch static-pod control plane + etcd ----
kubeadm init phase etcd local
kubeadm init phase control-plane all

# ---- 5. Bootstrap tokens for node joins ----
#
# Worker nodes present a bootstrap token, receive a CSR-signing
# grant from the controller-manager, kubelet generates an RSA-2048
# keypair locally and sends a CSR; the CSR signer (operated by the
# cluster CA's private key) issues the kubelet-client cert.
kubeadm init phase bootstrap-token --skip-token-print \
    --config /etc/kubernetes/kubeadm-config.yaml

# ---- 6. Install CNI + CoreDNS ----
kubectl --kubeconfig /etc/kubernetes/admin.conf \
    apply -f https://raw.githubusercontent.com/cilium/cilium/v1.15/install/kubernetes/quick-install.yaml

# ---- Breakage ----
#
# The cluster root CA (`/etc/kubernetes/pki/ca.key`) and the SA
# signing key (`/etc/kubernetes/pki/sa.key`) are a two-headed single
# point of trust for the whole cluster. An RSA factoring attack on:
#
#   - ca.key          → mint apiserver client certs with
#                       CN=system:masters, i.e. cluster-admin, bypass
#                       every RBAC policy in the cluster
#   - sa.key          → mint projected SA tokens as any ServiceAccount
#                       in any namespace — root on every secret in
#                       the cluster
#   - etcd/ca.key     → connect to etcd directly and read every
#                       Secret object at rest (EncryptionConfiguration
#                       mitigates, but is off by default)
#
# Kubernetes provides no key-rotation primitive short of cluster
# re-initialization.  A factoring-break response looks like
# "rebuild every control-plane + rotate every workload SA cert."
