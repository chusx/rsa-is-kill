# vault-pki — RSA-2048 default in cloud-native PKI

**Software:** HashiCorp Vault (hashicorp/vault) PKI secrets engine 
**Industry:** Cloud-native infrastructure, service mesh mTLS, Kubernetes cert issuance 
**Algorithm:** RSA-2048 (default key_type and key_bits) 

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
signing key. A factoring break breaking the root CA key can forge certificates for any
service in the entire Vault PKI hierarchy.

## Why it's stuck

- Go's `crypto/x509` has no non-RSA algorithm support (Go 1.22)
- No non-RSA `key_type` is accepted by the Vault PKI engine
- cert-manager (the Kubernetes cert issuance controller) has no non-RSA issuer support
- SPIFFE/SPIRE (service mesh identity) uses X.509 SVIDs — no non-RSA format defined
- Even if Vault added non-RSA, the receiving mTLS endpoints (Envoy, NGINX, Go services)
 cannot validate non-RSA certificates

## impact

Vault PKI is the internal certificate authority for cloud-native infrastructure. default key type is RSA-2048 with a 10-year root CA validity. everything in the cluster chains to that root.

- forge a TLS certificate for any internal service (payments-api.internal, auth.internal, whatever you want). MitM every microservice-to-microservice call in the service mesh. Istio and Consul Connect mutual TLS is the security boundary and it collapses
- forge a certificate for the Vault agent injector (the sidecar that delivers secrets to pods). intercept all secrets being injected: database passwords, API keys, other private keys
- the blast radius is the entire application stack. one compromised Vault root CA key gives MitM access to every mTLS-protected API call in the cluster
- Go's crypto/x509 has no non-RSA support. no non-RSA key_type in the Vault PKI engine. cert-manager has no non-RSA issuer. the entire ecosystem has to move simultaneously
## Code

`vault_pki_rsa_default.go` — `GeneratePrivateKey()` returning `rsa.GenerateKey()`
for the default `"rsa"` key type, with commentary on service mesh root CA validity
windows and the cert-manager / Istio deployment impact.
