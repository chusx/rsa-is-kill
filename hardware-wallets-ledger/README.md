# Hardware Wallets (Ledger) — secp256k1 ECDSA

**Source:** https://github.com/LedgerHQ/app-bitcoin-new (Apache-2.0)  
**SDK Reference:** https://developers.ledger.com/docs/device-app/references/cryptography-api  
**License:** Apache-2.0 (app) / proprietary (SDK internals)

## what it does

Ledger hardware wallets store private keys in a secure element (SE050 or proprietary ST chip) and sign cryptocurrency transactions on-device. The Bitcoin and Ethereum apps use `cx_ecdsa_sign()` with `CX_CURVE_256K1` (secp256k1) for all transaction signing.

## impact

hardware wallets protect the private key from software extraction. Shor's algorithm doesn't extract the private key, it derives it from the public key, which is permanently on the blockchain and has been there since the first transaction. the hardware wallet is completely irrelevant to this attack.

- cx_ecdsa_sign() with CX_CURVE_256K1 produces a secp256k1 signature. the corresponding public key is on-chain. the CRQC never needs to come anywhere near the hardware
- physical isolation, secure elements, PIN codes, seed phrase security: all irrelevant. the attack surface is the public blockchain, not the device
- Trezor Safe 7 added SLH-DSA for firmware signing (good). Bitcoin and Ethereum transactions still use secp256k1 because the blockchains require it (not good)
- Ledger says current secure element chips lack the processing power and memory for PQC operations. no existing Ledger can be upgraded to PQC via firmware. every Nano S, X, and S Plus ever sold is permanently secp256k1-only
- migration requires: blockchain hard fork to support PQC, new hardware with PQC-capable secure elements, and users migrating funds from old addresses. all three have to happen before the CRQC shows up
## migration status

Hardware can't be upgraded. Migration requires: (1) blockchain protocol hard fork to support PQC signatures, (2) new hardware wallet generation with PQC-capable secure elements, (3) users migrating funds from old to new addresses. All three must happen before a CRQC arrives.
