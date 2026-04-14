# Hardware Wallets (Ledger) — secp256k1 ECDSA

**Source:** https://github.com/LedgerHQ/app-bitcoin-new (Apache-2.0)  
**SDK Reference:** https://developers.ledger.com/docs/device-app/references/cryptography-api  
**License:** Apache-2.0 (app) / proprietary (SDK internals)

## what it does

Ledger hardware wallets store private keys in a secure element (SE050 or proprietary ST chip) and sign cryptocurrency transactions on-device. The Bitcoin and Ethereum apps use `cx_ecdsa_sign()` with `CX_CURVE_256K1` (secp256k1) for all transaction signing.

## why is this hella bad

Hardware wallets are designed to protect private keys from software extraction. They do nothing to protect against Shor's algorithm, which attacks the **public key** — which is permanently on the blockchain.

- `cx_ecdsa_sign()` with `CX_CURVE_256K1` produces a secp256k1 signature. The corresponding public key is on-chain.
- Shor's algorithm takes the public key and computes the private key. It never touches the hardware wallet.
- Physical isolation, secure elements, PIN codes, seed phrase backups — all irrelevant against a CRQC.
- The Trezor Safe 7 added SLH-DSA for **firmware signing** (the boot chain). Bitcoin/Ethereum transactions still use secp256k1 because the blockchain requires it.
- Ledger has stated that current secure element chips "lack the processing power and memory for PQC operations." No existing Ledger model can be upgraded to PQC via firmware.
- Every Ledger Nano S/X/S Plus ever sold is permanently secp256k1-only.

## migration status

Hardware can't be upgraded. Migration requires: (1) blockchain protocol hard fork to support PQC signatures, (2) new hardware wallet generation with PQC-capable secure elements, (3) users migrating funds from old to new addresses. All three must happen before a CRQC arrives.
