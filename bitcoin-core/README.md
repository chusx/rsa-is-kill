# Bitcoin Core — ECDSA over secp256k1

**Source:** https://github.com/bitcoin/bitcoin  
**File:** `src/key.cpp`  
**License:** MIT

## what it does

Every Bitcoin transaction is authorized by an ECDSA (or Schnorr) signature over the secp256k1 elliptic curve. `CKey::Sign()` is called every time a wallet spends a UTXO. The signature is included in the transaction and verified by every full node.

## impact

secp256k1 is broken by Shor's algorithm. a CRQC computes the private key from the public key. the blockchain is a public database of every public key ever used. these two facts combine badly.

- roughly 4 million BTC sit in P2PK outputs where the public key is directly on-chain and has been since forever. these are immediately spendable the moment a CRQC exists, no waiting
- P2PKH outputs only expose the public key when spent, but a CRQC could intercept a broadcast transaction and race to spend the coins before the original confirms. good luck winning that race against a quantum computer
- there is no migration path without a consensus hard fork. changing the signature scheme requires every node to upgrade simultaneously. good luck coordinating that under deadline pressure with billions of dollars at stake
- secp256k1_ecdsa_sign() is the single global signing primitive with no abstraction layer. there is no slot to bolt in ML-DSA
## migration status

No finalized BIP for quantum-resistant signatures. Proposed strategies include a hard fork with a deadline after which coins in vulnerable addresses are burned, or a soft fork introducing a new script type. Neither has consensus.
