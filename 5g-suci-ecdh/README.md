# 5g-suci-ecdh — ECDH subscriber identity concealment in 5G NR

**Standard:** 3GPP TS 33.501 §6.12, Annex C (5G Security Architecture)  
**Industry:** Mobile telecommunications — carriers, equipment vendors, SIM manufacturers  
**Algorithm:** ECDH secp256r1 (Profile B) or X25519 (Profile A) — both broken by Shor  
**PQC migration plan:** None — 3GPP SA3 has no PQC protection scheme; SUCI scheme IDs 0-2 only

## What it does

In 4G LTE, phones transmit their IMSI (permanent subscriber identity) in plaintext
over the radio interface, enabling IMSI catchers (Stingrays) to track anyone.
5G NR was designed to fix this. The SUCI (Subscription Concealed Identifier) is an
ECIES encryption of the IMSI using the Home Network's public key, so only the
carrier's core network (AUSF/UDM) can decrypt it.

The Home Network Public Key (HNPK) is provisioned into the SIM at manufacture
(stored in USIM EF SUCI Calc Info per ETSI TS 131 102). Two protection schemes:
- **Profile A:** X25519 (Curve25519 ECDH) + HKDF-SHA-256 + AES-128-CTR
- **Profile B:** secp256r1 (P-256 ECDH)  + HKDF-SHA-256 + AES-128-CTR

The UE encrypts the MSIN (Mobile Subscriber Identification Number) portion of the
SUPI to the HNPK. The UE's ephemeral public key is sent in the clear as part of the
SUCI. The carrier's AUSF/UDM decrypts it using the HNPK private key.

Every 5G Registration Request, handover, and paging response contains a SUCI.
There are 1.5+ billion 5G subscriptions as of 2025.

## Why it's stuck

- 3GPP TS 33.501 defines protection schemes 0x00 (null), 0x01 (Profile A), and 0x02
  (Profile B). No PQC scheme is defined. Scheme IDs 0x03-0xFF are reserved
- SA3 (3GPP Security group) has no active work item for a PQC SUCI protection scheme
  (as of Release 18/19)
- The HNPK is provisioned into SIM cards at manufacture or via SIM OTA update.
  SIM cards in IoT deployments have 10+ year lifespans
- X25519 and secp256r1 are both ECDH curves broken by Shor's algorithm. Profile A
  is not safer than Profile B against a CRQC — both are broken

## impact

5G SUCI was specifically designed to prevent subscriber tracking by passive observers.
a CRQC breaks this property. the entire 5G privacy architecture folds.

- factor the Home Network P-256 public key (available in every SIM issued by that
  carrier, readable with a SIM card reader), derive the HNPK private key, decrypt
  every SUCI ever transmitted. every registration request, every paging response,
  every handover — all map to a specific SUPI (IMSI)
- the result is a complete retrospective subscriber location database. every time
  a subscriber's phone connected to a cell tower is correlated to their real identity.
  this is exactly what 5G SUCI was designed to prevent
- the UE ephemeral public key is transmitted in cleartext as part of the SUCI format
  (3GPP TS 33.501 Annex C.4). the HNDL capture is trivial: just log the SUCI fields
  from 5G NR signaling. no active attack required, just passive recording
- IoT SIMs (embedded in vehicles, utility meters, industrial equipment) have
  10+ year lifespans and fixed HNPK provisioning. they cannot be updated without
  physical SIM replacement

## Code

`suci_ecdh_concealment.c` — `suci_scheme_b_conceal()` (UE-side ECDH P-256 ECIES
encryption of MSIN), `suci_scheme_b_decrypt()` (AUSF/UDM decryption using HNPK
private key), with notes on HNDL risk and 5G deployment scale.
