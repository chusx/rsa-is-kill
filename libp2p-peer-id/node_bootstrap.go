// node_bootstrap.go
//
// libp2p host bootstrap + peer discovery + secure-channel upgrade.
// Wraps the RSA-based PeerID derivation in `libp2p_rsa_peerid.go` and
// shows the integration path every libp2p-speaking node takes when
// it joins a network.
//
// Live production networks riding this exact code path:
//   - IPFS (go-ipfs / Kubo) — tens of millions of hosts over time,
//     hundreds of thousands concurrent, ~public bootstrap nodes operated
//     by Protocol Labs + community
//   - Filecoin mainnet (Lotus node) — every storage + retrieval miner
//     and client
//   - Ethereum Consensus Layer p2p (Lighthouse, Teku, Nimbus, Prysm,
//     Lodestar use libp2p for gossipsub + beacon p2p; Ethereum node
//     identity = libp2p PeerID, frequently still RSA in older
//     deployments)
//   - Polkadot / Substrate (sc-network uses libp2p)
//   - Cosmos-SDK chains using CometBFT p2p layer (Celestia, Osmosis,
//     Akash) for some comms paths
//   - Textile, Fleek, Pinata — hosted IPFS providers
//   - Pocket Network, Arweave gateway mesh

package main

import (
	"context"
	"crypto/rand"

	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	host "github.com/libp2p/go-libp2p/core/host"
	peer "github.com/libp2p/go-libp2p/core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	tls "github.com/libp2p/go-libp2p/p2p/security/tls"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"
)

// Bootstrap peers — the fixed list every IPFS node dials at startup
// to enter the Kademlia DHT. These are operated by Protocol Labs /
// community.  All have stable RSA-2048 PeerIDs dating to early IPFS
// mainnet.
var IPFSBootstrap = []string{
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
}

func RunNode(ctx context.Context, keyStorePath string) (host.Host, error) {
	// 1. Load or generate the node's identity keypair.  Older IPFS
	//    nodes default to RSA-2048 (preserves PeerID stability across
	//    Kubo upgrades); Ed25519 is the modern default but RSA keys
	//    remain pervasive on the network.
	priv, err := loadOrGenerateRSAIdentity(keyStorePath)
	if err != nil {
		return nil, err
	}

	// 2. Bring up the libp2p host with TLS + Noise transports. Both
	//    transports use the identity key for peer authentication —
	//    TLS wraps the key into an X.509 extension ("libp2p Public
	//    Key Extension"), Noise uses it as the static XX key.
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/4001",
			"/ip4/0.0.0.0/udp/4001/quic-v1",
		),
		libp2p.Security(tls.ID, tls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.NATPortMap(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		return nil, err
	}

	// 3. DHT: Kademlia peer routing + CID providing.
	kad, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto))
	if err != nil {
		return nil, err
	}
	if err := kad.Bootstrap(ctx); err != nil {
		return nil, err
	}

	// 4. Dial bootstrap peers.
	for _, addr := range IPFSBootstrap {
		ma, _ := multiaddr.NewMultiaddr(addr)
		pi, _ := peer.AddrInfoFromP2pAddr(ma)
		go h.Connect(ctx, *pi)
	}

	return h, nil
}

// loadOrGenerateRSAIdentity is a wrapper around the primitive in
// libp2p_rsa_peerid.go. First-run nodes get a fresh RSA-2048 keypair
// and persist it; subsequent runs reload so the PeerID is stable
// across restarts (critical for DHT provider records, peering
// relationships, IPNS ownership).
func loadOrGenerateRSAIdentity(path string) (crypto.PrivKey, error) {
	if priv, err := tryLoad(path); err == nil {
		return priv, nil
	}
	priv, _, err := crypto.GenerateKeyPairWithReader(
		crypto.RSA, 2048, rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, persist(priv, path)
}

func tryLoad(path string) (crypto.PrivKey, error) { return nil, nil }
func persist(priv crypto.PrivKey, path string) error { return nil }

// ---- Breakage ----
//
// Every libp2p node authenticates peers via libp2p-TLS (RFC draft)
// where the leaf cert embeds the PeerID's public key. A factoring
// attack against any RSA-based PeerID lets an attacker impersonate
// that peer to every other peer on the network:
//
//   - IPNS record forgery: attacker publishes IPNS names under any
//     RSA PeerID they've factored; downstream resolvers (including
//     every IPFS gateway — ipfs.io, cf-ipfs.com, dweb.link) serve
//     the attacker's content under the victim's stable name.
//   - Filecoin provider impersonation: take over a miner's PeerID
//     and sign deal proposals / retrievals as that miner.
//   - Ethereum CL node takeover: a factored validator-adjacent RSA
//     key lets an attacker sybil into the mesh and drown-out
//     attestations for a target validator.
//
// The IPFS network has been migrating to Ed25519 PeerIDs for years,
// but the long tail of RSA-2048 PeerIDs on mainnet is still large.
