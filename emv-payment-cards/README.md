# emv-payment-cards — RSA in 10 billion payment chips

**Standard:** EMV Book 2 (Security and Key Management) — Visa, Mastercard, Amex, UnionPay 
**Industry:** Retail payments, ATMs, contactless transit 
**Algorithm:** RSA-1024 (SDA/legacy), RSA-2048 (DDA/CDA), RSA-1152 (Visa CA keys) 

## What it does

EMV is the global chip payment standard. Every chip-and-PIN and contactless
payment card implements one of three RSA-based card authentication mechanisms:

| Mechanism | RSA use | Breaks with a factoring break |
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
 but only if migration begins before a factoring break emerges

## impact

EMV chip security is built on the premise that the ICC private key never leaves the chip. the factoring algorithm derives it from the public key, which is published in the certificate chain flowing through every single transaction.

- SDA cards use RSA-1024 for the issuer CA. factor that key and forge the Signed Static Application Data for every card that bank ever issued. unlimited card cloning in software, no physical card required
- DDA/CDA cards use RSA-2048 ICC signatures. recover the ICC private key from the certificate in the transaction flow and forge dynamic signatures indefinitely, passing terminal auth as any card
- the forged RSA signature is mathematically valid. the terminal has no way to distinguish it from the real thing. there's no alert, no anomaly, nothing
- compromising one issuer CA RSA key affects every card that bank issued. compromising the Visa or Mastercard root CA affects every card on the entire network
## Code

`emv_rsa_card_auth.c` — `emv_verify_sda()` (RSA public key operation on CA key
to verify issuer cert chain) and `emv_verify_dda()` (dynamic transaction
signing with ICC RSA private key), with the `EMV_CA_PublicKey` struct.
