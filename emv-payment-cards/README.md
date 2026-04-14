# emv-payment-cards — RSA in 10 billion payment chips

**Standard:** EMV Book 2 (Security and Key Management) — Visa, Mastercard, Amex, UnionPay  
**Industry:** Retail payments, ATMs, contactless transit  
**Algorithm:** RSA-1024 (SDA/legacy), RSA-2048 (DDA/CDA), RSA-1152 (Visa CA keys)  
**PQC migration plan:** None — no PQC algorithm defined in any EMV specification

## What it does

EMV is the global chip payment standard. Every chip-and-PIN and contactless
payment card implements one of three RSA-based card authentication mechanisms:

| Mechanism | RSA use | Breaks with CRQC |
|---|---|---|
| SDA (Static) | CA signs static card data at issuance | Factor CA key → forge any card |
| DDA (Dynamic) | Card has RSA keypair; signs terminal challenge | Factor card pubkey → clone card |
| CDA (Combined) | RSA over transaction + ARQC | Factor card pubkey → forge transactions |

The trust chain is entirely RSA:
```
Visa/MC Root CA (RSA-2048) → Issuer CA (RSA-2048) → ICC key (RSA-2048)
```

Visa CA index 07 uses a 1152-bit modulus — a non-standard size still larger
than classically-broken RSA-1024 but less common than 2048-bit. Several
legacy SDA cards still use RSA-1024 for the static data signature.

## Why it's stuck

- ~10 billion EMV cards globally; 3-5 year replacement cycle
- Migration requires coordinated spec update across Visa, Mastercard, Amex, UnionPay
- Every payment terminal (10M+ worldwide) must accept the new certificate format
- Every card personalization bureau HSM must be updated
- The relatively short card lifespan is actually the most favorable factor —
  but only if migration begins before a CRQC emerges

## why is this hella bad

- **SDA cards (RSA-1024)**: factor the issuing bank CA RSA-1024 key → forge the Signed Static Application Data for *any* card issued by that bank → unlimited card cloning in software, no physical access required
- **DDA/CDA cards (RSA-2048)**: recover each card's ICC private key from its certificate (embedded in the transaction flow) → forge dynamic signatures → pass terminal authentication as that card indefinitely
- Attack is **invisible at the terminal**: the forged RSA signature is mathematically valid, no behavioral anomaly
- Scale: compromising a single issuer CA RSA key affects every card issued by that bank (potentially millions). Compromising Visa/Mastercard root CA RSA key affects *every card on the network*
- At ~$10 trillion in annual card transaction volume, even 0.01% fraud represents $1 billion/year

## Code

`emv_rsa_card_auth.c` — `emv_verify_sda()` (RSA public key operation on CA key
to verify issuer cert chain) and `emv_verify_dda()` (dynamic transaction
signing with ICC RSA private key), with the `EMV_CA_PublicKey` struct.
