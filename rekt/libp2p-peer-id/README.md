# libp2p-peer-id — RSA-2048 permanent peer identity in IPFS / Filecoin

**Software:** libp2p/go-libp2p (and rust-libp2p, js-libp2p) 
**Industry:** Decentralized storage, Web3, IPFS, Filecoin 
**Algorithm:** RSA-2048 (legacy peer identity) — SHA-256(protobuf(pubkey)) = peer ID 

## What it does

Every libp2p node has a permanent identity derived from a cryptographic keypair.
The peer ID is the SHA-256 multihash of the protobuf-encoded public key. Peer IDs
are permanent identifiers used in the DHT, gossipsub, content routing, and every
libp2p connection handshake.

RSA-2048 was the original default key type for IPFS (`ipfs init` before go-ipfs 0.9.0
in 2021 defaulted to RSA-2048). Ed25519 is now the default for new nodes, but:
- Long-running IPFS infrastructure nodes initialized before 2021 still use RSA-2048
- IPFS gateway operators (Cloudflare, Pinata, Infura) run nodes with historical RSA keys
- Filecoin storage providers use libp2p for peer communication

During the libp2p Noise (XX pattern) or TLS 1.3 handshake, peers sign a payload
with their private key to prove possession of the key corresponding to their peer ID.
A factoring break can derive the private key from the public peer ID, then impersonate any peer.

## Why it's stuck

- The libp2p peer ID format is content-addressed: peer ID = hash(pubkey). Changing
 the key algorithm changes the peer ID — it's a new identity, not a migration
- No non-RSA key type is defined in the libp2p-crypto spec or in any active proposal
- Long-running nodes (storage providers, gateways) cannot easily rotate their peer ID
 because it's used as their persistent network identity in DHT routing tables,
 reputation systems, and client configurations
- The Filecoin network has no mechanism to update storage provider peer IDs without
 re-registering as a new provider (losing deal history and reputation)

## impact

libp2p peer IDs are published in the DHT and embedded in IPFS content paths.
the RSA-2048 public keys behind those peer IDs are readable by anyone in the network.

- factor any RSA-2048 peer's public key (from the DHT or IPFS peer exchange),
 derive the private key, impersonate that peer in all libp2p connections. inject
 arbitrary data into IPFS content streams from that peer ID
- for Filecoin storage providers: the libp2p peer identity is the provider's
 on-chain identity for deal negotiation. impersonate a storage provider, intercept
 storage deals, forge storage proofs, steal rewards. larger providers have
 petabytes of storage and significant on-chain stake
- IPFS content routing uses the DHT. impersonate DHT nodes to redirect content
 queries, censor content, or serve malicious content under legitimate CIDs
- libp2p is used beyond IPFS: Ethereum 2 (Lighthouse, Prysm) uses libp2p for
 validator networking. impersonate validators, disrupt consensus gossip, inject
 fake attestations. ETH2 validator keys are separate but the p2p layer is libp2p

## Code

`libp2p_rsa_peerid.go` — `GenerateRSAKeyPair()` (RSA-2048 identity keypair),
`IDFromPublicKey()` (SHA-256 multihash derivation for RSA keys), `RsaPublicKey.Verify()`
(PKCS#1 v1.5 signature verification during Noise handshake), and notes on Filecoin
storage provider impact.
