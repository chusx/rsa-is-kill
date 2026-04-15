# vault_pki_integration.hcl
#
# HashiCorp Vault PKI secrets engine config + consumer workflows. The
# primitive in `vault_pki_rsa_default.go` is invoked on every leaf
# cert issuance.  Vault's PKI engine is the enterprise-internal CA
# of record at: HashiCorp's own SaaS (HCP), Adobe, Shopify, Cloudflare
# (internal), Datadog, Stripe, most of the Fortune-500 cloud-native
# shops that standardized on Vault + Consul + Terraform.
#
# The engine mints: mTLS service-to-service certs (Istio / Linkerd
# sidecars when not using SPIFFE SVIDs), Kubernetes control-plane
# certs (kube-apiserver, etcd peer/client), developer short-lived
# client certs issued via `vault pki issue`, Kafka broker/client
# certs for TLS-authenticated Kafka (RedPanda, MSK, Confluent), and
# machine-identity SSH-cert-signing workflows.

# ---- Mount the root + intermediate PKI engines ---------------------

path "sys/mounts/pki_root" {
  capabilities = ["create", "update"]
}

path "sys/mounts/pki_int" {
  capabilities = ["create", "update"]
}

# Root CA: generated once, offline sign ceremony, HSM-backed.
# Cross-signs the intermediates that actually issue leaves.
resource "vault_pki_secret_backend" "root" {
  path         = "pki_root"
  type         = "pki"
  max_lease_ttl_seconds = 315360000  # 10 years
}

resource "vault_pki_secret_backend_root_cert" "root_ca" {
  backend     = vault_pki_secret_backend.root.path
  type        = "internal"
  common_name = "Corp Root CA"
  ttl         = "87600h"
  key_type    = "rsa"      # RSA-4096 per enterprise-CA standing order
  key_bits    = 4096
  organization = "Corp Inc."
}

# Intermediate: the issuer that mints day-to-day leaves.
resource "vault_pki_secret_backend" "intermediate" {
  path         = "pki_int"
  type         = "pki"
  max_lease_ttl_seconds = 157680000  # 5 years
}

resource "vault_pki_secret_backend_intermediate_cert_request" "csr" {
  backend     = vault_pki_secret_backend.intermediate.path
  type        = "internal"
  common_name = "Corp Services Issuing CA"
  key_type    = "rsa"
  key_bits    = 4096
}

resource "vault_pki_secret_backend_root_sign_intermediate" "sign" {
  backend     = vault_pki_secret_backend.root.path
  csr         = vault_pki_secret_backend_intermediate_cert_request.csr.csr
  common_name = "Corp Services Issuing CA"
  ttl         = "43800h"
}

# ---- Role: per-service cert profile ---------------------------------
resource "vault_pki_secret_backend_role" "service_leaf" {
  backend            = vault_pki_secret_backend.intermediate.path
  name               = "svc"
  max_ttl            = "720h"   # 30 days
  ttl                = "168h"   # 7 days default
  allow_any_name     = false
  allowed_domains    = ["svc.cluster.local", "corp.example.com"]
  allow_subdomains   = true
  key_type           = "rsa"
  key_bits           = 2048
  use_csr_common_name = true
  server_flag        = true
  client_flag        = true
}

# ---- AppRole + policy for issuing agents ----------------------------
resource "vault_policy" "svc_pki_issuer" {
  name   = "svc-pki-issuer"
  policy = <<EOT
    path "pki_int/issue/svc" { capabilities = ["update"] }
    path "pki_int/ca_chain"  { capabilities = ["read"]   }
  EOT
}

# ---- Downstream consumers -------------------------------------------
#
# 1. Kubernetes (via cert-manager Vault issuer):
#    cert-manager walks `Certificate` CRDs, calls `vault write
#    pki_int/issue/svc` with the CSR, receives a 7-day RSA-2048 leaf,
#    renews via daily reconciliation.
#
# 2. Consul Connect sidecar proxies:
#    Consul's connect-ca provider mode = "vault" — every envoy
#    sidecar's mTLS cert is minted by this engine, RSA-2048 leaf.
#
# 3. Nomad Vault integration:
#    `vault.template` stanza renders leaves onto disk for legacy
#    workloads that don't speak Vault natively.
#
# 4. SSH cert auth:
#    pki_int/sign-ssh for user-facing bastion access; the CA
#    signature is RSA-2048 or RSA-4096 per role config.
#
# 5. Cross-plane Crossplane / ArgoCD / Flux:
#    webhook admission controllers and controller webhook certs are
#    issued here as well.

# ---- Rotation / expiry monitoring -----------------------------------
#
#   vault pki health-check -format=json pki_int | jq .
#   vault list pki_int/certs                        # tail of issued certs
#   prom-exporter "vault_pki_cert_expiry_seconds"   # alert <21d
#   annual: rotate intermediate via cross-sign + tidy

# ---- Breakage --------------------------------------------------------
#
# A factoring attack against:
#
# - **The Corp Root CA (RSA-4096)**: attacker mints an intermediate,
#   mints arbitrary leaves, MITM's every mTLS service-to-service
#   call, forges admission-controller certs and installs poisoned
#   workloads into Kubernetes clusters, signs rogue SSH user certs.
#   Entire enterprise zero-trust posture collapses in a single
#   compromise.
#
# - **The intermediate issuing CA**: same kind of leaf forging, but
#   revocable by re-issuing the intermediate from the root. Downtime
#   = however long it takes to propagate the new chain to every
#   service (hours to days at scale).
#
# - **An individual service leaf**: targeted sidecar MITM, one
#   service's TLS traffic exposed. 7-day TTL limits the window, but
#   factoring a fresh key daily just means the break is permanent
#   not bounded.
