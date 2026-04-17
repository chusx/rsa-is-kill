// router_rtr_consumer.go
//
// How a BGP speaker (route reflector, edge router) actually uses the
// RSA-validated ROAs produced by `rpki_rsa_verify.rs`. RTR (RPKI-To-
// Router, RFC 8210bis) is the consumer protocol that pulls validated
// prefix-origin data from Routinator / Fort / OctoRPKI / rpki-client
// into the router's RIB.
//
// Deployed on: Cloudflare, Amazon, Google, Microsoft, Facebook, and
// every major transit provider (NTT, Lumen/Level3, Cogent, Telia,
// GTT, Zayo, HE) route reflectors. Tier-1 transit peers mutually
// enforce ROV (Route Origin Validation) at the IRR/RPKI boundary,
// dropping or deprioritizing any BGP announcement whose origin ASN
// doesn't match a valid ROA.
//
// End-to-end trust chain:
//   IANA TAL (RSA-2048) → 5x RIR TA certs (RSA-2048 each) → regional
//   allocations → member orgs → signed ROA objects
// Every link is an RSA signature. `rpki_rsa_verify.rs` validates
// them end-to-end before emitting RTR payloads.

package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bgp/stayrtr/protocol"
	"github.com/bgp/stayrtr/lib"
	"github.com/osrg/gobgp/v3/pkg/server"
)

// RouterBGPROVEnforcer is the piece running inside a route-reflector
// process: pulls RPKI data over RTR, then gates BGP UPDATE acceptance
// on validation results.
type RouterBGPROVEnforcer struct {
	rtrClient  *lib.ClientSession
	bgpServer  *server.BgpServer
	validationCache *lib.VRPManager
}

func (r *RouterBGPROVEnforcer) Start(ctx context.Context,
	rtrEndpoints []string) error {

	// 1. Connect to the local validator's RTR endpoint (Routinator
	//    default port 3323).  Validator-side RPKI/RSA proof-checking
	//    happens in `rpki_rsa_verify.rs`; RTR streams the already-
	//    validated VRP (Validated ROA Payload) list over TCP.
	r.rtrClient = lib.NewClientSession(rtrEndpoints[0],
		lib.WithRefresh(60*time.Second),
		lib.WithOnVRPUpdate(r.onValidatedROAs))
	if err := r.rtrClient.Dial(ctx); err != nil {
		return fmt.Errorf("rtr dial: %w", err)
	}

	// 2. Install BGP policy hook — every inbound UPDATE gets
	//    its origin ASN cross-checked against the in-memory VRP
	//    set. Invalid routes are tagged Invalid and either
	//    dropped, deprioritized, or localpref=0'd per the
	//    operator's policy.
	r.bgpServer.SetPolicy(r.buildROVPolicy())
	return nil
}

// onValidatedROAs is called whenever Routinator pushes a serial
// increment.  The VRP list contains tuples (prefix, maxLen, ASN).
func (r *RouterBGPROVEnforcer) onValidatedROAs(vrps []lib.VRP) {
	r.validationCache.ReplaceAll(vrps)
	// Trigger BGP RIB re-evaluation so that existing prefixes get
	// their validation state recomputed under the new ROA set.
	r.bgpServer.SoftReconfigAllPeers()
}

// buildROVPolicy materializes the route-import policy every peer uses.
func (r *RouterBGPROVEnforcer) buildROVPolicy() any {
	// Pseudocode-ish:
	//   if rpki-state == Valid     → allow, bump localpref +50
	//   if rpki-state == NotFound  → allow, no change
	//   if rpki-state == Invalid   → drop  (transit peers)
	//                              | localpref 0 (customer cone)
	return map[string]string{
		"valid":    "permit localpref +50",
		"notfound": "permit",
		"invalid":  "deny",
	}
}

// ---- Operational facts ----
//
// - Cloudflare "Is BGP safe yet?" (isbgpsafeyet.com) tracks ROV
//   adoption on the public internet; enforcement crossed 50% of
//   globally routed traffic in 2023.
// - AWS enforces ROV on every IX peering + every customer-facing
//   Direct Connect; an Invalid origin is dropped, not deprioritized.
// - Hyperscaler route reflectors run tens of thousands of RTR
//   sessions across their backbone.
//
// ---- Breakage ----
//
// Every trust-chain link from the IANA TAL down to the leaf ROA is
// an RSA signature. A factoring attack against:
//
//   - IANA/RIR root TALs: an attacker mints a fake RIR → fake member
//     org → fake ROA claiming e.g. "ASN 13335 is authorized origin
//     for 1.1.1.0/24" and pushes it into the global RPKI.  Validators
//     serve it as authoritative; every ROV-enforcing router on the
//     planet accepts the forged origin and prefers it over the
//     legitimate one.  Pre-RPKI BGP hijacks (YouTube 2008, AS7007
//     1997, etc.) become trivially revivable.
//
//   - A single member's CA: an attacker hijacks that member's
//     prefixes specifically — targeted financial institution
//     de-peering, cryptocurrency exchange BGP hijacks (cf. MyEtherWallet
//     2018), nation-state censorship re-routes.
//
// The IANA + RIR TALs are among the single most consequential RSA
// keys in global networking.  A factoring break has internet-scale
// BGP security implications on the order of the dnssec / web-PKI
// roots.
