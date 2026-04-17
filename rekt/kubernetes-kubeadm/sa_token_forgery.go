/*
 * sa_token_forgery.go
 *
 * Kubernetes ServiceAccount token minting and validation.
 * kubeadm generates an RSA-2048 SA signing key pair during
 * cluster bootstrap (see cluster_bootstrap.sh in this dir);
 * every ServiceAccount JWT is RS256-signed under this key.
 *
 * The public key is published at /openid/v1/jwks on the API
 * server (and in --service-account-key-file on every node).
 * Any entity with the factored private key can mint tokens
 * with arbitrary claims: namespace, serviceaccount name,
 * audiences, and expiry.
 *
 * ~500k+ Kubernetes clusters run kubeadm-generated SA keys;
 * EKS/AKS/GKE use similar RSA-based OIDC issuers. The
 * published JWKS endpoint is the factoring input.
 */
package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// JWK as published at /openid/v1/jwks on the API server.
type JWK struct {
	Kty string `json:"kty"` // "RSA"
	Alg string `json:"alg"` // "RS256"
	Use string `json:"use"` // "sig"
	Kid string `json:"kid"`
	N   string `json:"n"` // modulus, base64url
	E   string `json:"e"` // exponent, base64url
}

// ServiceAccountClaims — the JWT payload of a k8s SA token.
type ServiceAccountClaims struct {
	Iss string   `json:"iss"`                   // "https://kubernetes.default.svc"
	Sub string   `json:"sub"`                   // "system:serviceaccount:ns:name"
	Aud []string `json:"aud"`                   // ["https://kubernetes.default.svc"]
	Exp int64    `json:"exp"`
	Iat int64    `json:"iat"`
	Nbf int64    `json:"nbf"`
	// k8s-specific private claims
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid"`
	PodName            string `json:"kubernetes.io/pod/name,omitempty"`
	NodeName           string `json:"kubernetes.io/node/name,omitempty"`
}

// FetchJWKS retrieves the cluster's public SA signing key
// from the unauthenticated JWKS endpoint.
func FetchJWKS(apiServer string) (*rsa.PublicKey, error) {
	// GET https://<api-server>/openid/v1/jwks
	// This endpoint is unauthenticated by design (OIDC spec).
	body := httpGet(fmt.Sprintf("%s/openid/v1/jwks", apiServer))
	var keys struct{ Keys []JWK }
	json.Unmarshal(body, &keys)
	k := keys.Keys[0]
	nBytes, _ := base64.RawURLEncoding.DecodeString(k.N)
	eBytes, _ := base64.RawURLEncoding.DecodeString(k.E)
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	return &rsa.PublicKey{N: n, E: e}, nil
}

// ValidateSAToken is the API server's token authenticator
// (pkg/serviceaccount/jwt.go). Every API request carrying a
// Bearer token is validated here.
func ValidateSAToken(tokenStr string, pubKey *rsa.PublicKey) (*ServiceAccountClaims, error) {
	parts := splitJWT(tokenStr) // header.payload.signature
	signed := parts[0] + "." + parts[1]
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])

	// RS256 verification — the sole crypto gate
	h := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pubKey, 0 /*SHA256*/, h[:], sig); err != nil {
		return nil, fmt.Errorf("token signature invalid: %w", err)
	}

	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims ServiceAccountClaims
	json.Unmarshal(payload, &claims)
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}

// RBAC gate: the returned claims.Sub is matched against
// ClusterRoleBindings / RoleBindings. For example:
//   sub = "system:serviceaccount:kube-system:coredns"
// has a ClusterRoleBinding granting list/watch on endpoints.
//
// An attacker who can forge tokens mints:
//   sub = "system:serviceaccount:kube-system:cluster-admin"
// and the RBAC evaluator grants full cluster-admin.

// ---- Break surface when SA signing key is factored --------
//
// Input: the RSA-2048 modulus from /openid/v1/jwks (public).
// Output: mint JWTs with any claims:
//   * cluster-admin SA -> full control of all namespaces
//   * node-bootstrapper SA -> register rogue kubelets
//   * pod-eviction SA -> disrupt workloads
//   * custom SA -> access secrets, configmaps, PVCs
//
// Detection: audit logs show the SA name but the token
// validates cryptographically; distinguishing forged from
// legitimate requires behavioral analysis.
//
// Recovery: rotate SA signing key (kubeadm certs renew),
// restart API server, and invalidate every in-flight token.
// Every pod using projected SA tokens must restart. In a
// large cluster (5k+ nodes) this is a rolling-restart event
// measured in hours with production impact.
// --------------------------------------------------------- */

func httpGet(url string) []byte                   { return nil }
func splitJWT(s string) [3]string                 { return [3]string{} }
