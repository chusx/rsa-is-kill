# go-ethereum — secp256k1 ECDSA

**Source:** https://github.com/ethereum/go-ethereum  
**Files:** `crypto/crypto.go`, `crypto/signature_cgo.go`  
**License:** LGPL-2.1

## what it does

Ethereum's cryptographic identity is built entirely on secp256k1. An Ethereum address is defined as the last 20 bytes of Keccak-256(public key), where the public key is a secp256k1 point. Every transaction, every EIP-712 typed signature, every ERC-20 approval is an ECDSA signature over secp256k1.

## why it's broken

- `S256()` is the only curve in the codebase. `GenerateKey()` hardwires it. `toECDSA()` hardwires it. `Sign()` delegates to the C secp256k1 library with no abstraction.
- An Ethereum "address" is cryptographically bound to secp256k1. Changing the signing scheme changes what an address means — this is a protocol-level identity break, not just an algorithm swap.
- Over 200 million Ethereum addresses hold value. Every one is a secp256k1 public key hash — all vulnerable.
- The `secp256k1halfN` malleability check and `Ecrecover()` function are secp256k1-specific mathematical properties that have no direct equivalent in lattice cryptography.

## migration status

Vitalik Buterin has proposed account abstraction (ERC-4337 / EIP-7702) as an eventual escape hatch, allowing accounts to use arbitrary verification logic including PQC. As of 2026 this is optional and very few accounts use it. All standard EOAs (externally owned accounts) remain secp256k1 only.
