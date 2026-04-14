# Bitcoin Core — ECDSA over secp256k1

**Source:** https://github.com/bitcoin/bitcoin  
**File:** `src/key.cpp`  
**License:** MIT

## what it does

Every Bitcoin transaction is authorized by an ECDSA (or Schnorr) signature over the secp256k1 elliptic curve. `CKey::Sign()` is called every time a wallet spends a UTXO. The signature is included in the transaction and verified by every full node.

## why it's broken

- secp256k1 ECDSA is broken by Shor's algorithm. A CRQC can compute the private key from a public key in polynomial time.
- **~4 million BTC** sit in P2PK outputs where the public key is directly exposed on-chain — these are immediately spendable by a CRQC operator without waiting for a transaction to appear.
- P2PKH outputs expose the public key only when spent, but a CRQC could intercept a broadcast transaction and race to spend the coins before the original transaction confirms.
- There is no migration path without a consensus hard fork. Changing the signature scheme requires every node on the network to upgrade simultaneously.
- `secp256k1_ecdsa_sign()` with RFC 6979 nonce generation is the single global signing primitive — there is no abstraction layer, no algorithm negotiation.

## migration status

No finalized BIP for quantum-resistant signatures. Proposed strategies include a hard fork with a deadline after which coins in vulnerable addresses are burned, or a soft fork introducing a new script type. Neither has consensus.
