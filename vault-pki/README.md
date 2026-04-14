# vault-pki — RSA-2048 default in cloud-native PKI

**Software:** HashiCorp Vault (hashicorp/vault) PKI secrets engine  
**Industry:** Cloud-native infrastructure, service mesh mTLS, Kubernetes cert issuance  
**Algorithm:** RSA-2048 (default key_type and key_bits)  
**PQC migration plan:** None — Go crypto/x509 has no PQC support; Vault 1.17 has no PQC issuer

## What it does

HashiCorp Vault is the dominant secrets management platform in cloud-native
infrastructure. Its PKI secrets engine acts as an internal CA for:

- **Service mesh mTLS**: Consul Connect, Istio (via cert-manager + Vault CA)
- **Kubernetes**: cert-manager issues TLS certs for every Ingress and Service
- **SSH certificate authorities**: short-lived SSH certs replacing static keys
- **Database credentials**: client certificates for mTLS to Postgres/MySQL
- **Internal enterprise CAs**: replacing Windows ADCS in many organizations

Default behavior: `vault write pki/root/generate/internal key_type=rsa key_bits=2048 ttl=87600h`
→ RSA-2048 root CA with 10-year validity.

Everything issued under that root (intermediates, leaf certs) chains to an RSA
signing key. A CRQC breaking the root CA key can forge certificates for any
service in the entire Vault PKI hierarchy.

## Why it's stuck

- Go's `crypto/x509` has no PQC algorithm support (Go 1.22)
- No PQC `key_type` is accepted by the Vault PKI engine
- cert-manager (the Kubernetes cert issuance controller) has no PQC issuer support
- SPIFFE/SPIRE (service mesh identity) uses X.509 SVIDs — no PQC format defined
- Even if Vault added PQC, the receiving mTLS endpoints (Envoy, NGINX, Go services)
  cannot validate PQC certificates

## why is this hella bad

Vault PKI is the internal certificate authority for cloud-native infrastructure. When the RSA-2048 root CA key falls:

- **Forge TLS certificates for any internal service**: forge a cert for `payments-api.internal` → MitM every microservice-to-microservice payment call in the service mesh
- **Poison Kubernetes secret delivery**: forge a cert for the Vault agent injector → intercept all secrets being injected into pods (database passwords, API keys, other private keys)
- **Break service mesh mTLS**: Consul Connect and Istio use Vault-issued certs for mutual TLS between every service. Forge any service's identity → accepted as legitimate by every other service
- The blast radius is the entire application infrastructure, not a single service. One compromised Vault root CA key gives MitM access to every mTLS-protected API call in the cluster

## Code

`vault_pki_rsa_default.go` — `GeneratePrivateKey()` returning `rsa.GenerateKey()`
for the default `"rsa"` key type, with commentary on service mesh root CA validity
windows and the cert-manager / Istio deployment impact.
