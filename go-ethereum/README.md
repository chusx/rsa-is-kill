# go-ethereum — secp256k1 ECDSA

**Source:** https://github.com/ethereum/go-ethereum  
**Files:** `crypto/crypto.go`, `crypto/signature_cgo.go`  
**License:** LGPL-2.1

## what it does

Ethereum's cryptographic identity is built entirely on secp256k1. An Ethereum address is defined as the last 20 bytes of Keccak-256(public key), where the public key is a secp256k1 point. Every transaction, every EIP-712 typed signature, every ERC-20 approval is an ECDSA signature over secp256k1.

## impact

Ethereum addresses are cryptographically bound to secp256k1. changing the signature scheme changes what an address *means* at the protocol level. there are 200 million addresses holding value and no migration path.

- S256() is the only curve in go-ethereum. GenerateKey() hardwires it. Sign() delegates to the C secp256k1 library. there is no abstraction layer, no algorithm negotiation, nowhere to insert ML-DSA
- an Ethereum address is a keccak hash of a secp256k1 public key. Shor's algorithm takes that public key and produces the private key. every address with a nonzero balance is a target
- secp256k1halfN and Ecrecover() are secp256k1-specific mathematical properties with no equivalent in lattice cryptography. migration is a protocol redesign, not a parameter swap
- account abstraction (ERC-4337/EIP-7702) exists as an eventual escape hatch but is optional and barely deployed. all standard EOAs remain secp256k1 only
## migration status

Vitalik Buterin has proposed account abstraction (ERC-4337 / EIP-7702) as an eventual escape hatch, allowing accounts to use arbitrary verification logic including PQC. As of 2026 this is optional and very few accounts use it. All standard EOAs (externally owned accounts) remain secp256k1 only.
