# PCI PTS POS terminals — signed firmware & remote key injection

Every card-accepting merchant on earth runs one of:

- **Verifone** (V200c, V400m, X990, Engage P-series, MX/M-series)
- **Ingenico** (Desk/5000, Move/5000, Lane/5000, Tetra, AXium)
- **PAX Technology** (A-series: A920, A80, A35, Aries8)
- **Newland, Castles, BBPOS, Equinox** (formerly Hypercom), **Clover**
  (owned by Fiserv), **Square Terminal**

All are certified to **PCI PTS POI** (PIN Transaction Security —
Point Of Interaction), a standard that mandates RSA-signed firmware,
PIN-block encryption under injected keys, and tamper-responsive
hardware. Global installed base: ~120 million terminals.

## RSA touchpoints

### 1. Signed firmware
Every application (EMV L2 kernel, PAX Android POS app, Verifone
Engage Terminal OS) is RSA-signed by the terminal vendor's code-
signing HSM. Terminal secure bootloader verifies the signature
(typically RSA-2048; some 2022+ products use RSA-3072).

### 2. Remote Key Injection (RKI)
POS terminals, like ATMs, load their symmetric PIN-encryption keys
via TR-34 or the older TR-31 (for key-exchange between HSMs in the
acquirer side). The initial RSA keypair is generated inside the
tamper-responsive POI during manufacture and the public half is
certified by the vendor CA. The acquirer's key injection facility
(KIF) or its Remote Key Injection platform (RKMS, DUKPT-injector)
wraps the Initial PIN Encryption Key (IPEK, per ANSI X9.24-3 BDK-
derived) to the terminal's RSA public key.

### 3. P2PE (Point-to-Point Encryption) session keys
P2PE v3 validates that card-data encryption happens inside the SCR
(Secure Card Reader) module, and the KDH-to-POI channel for key
rotation uses RSA-wrapped session keys.

### 4. Acquirer comms
Every authorization message (ISO 8583, Visa Base I/II, Mastercard
IPM, Amex, Discover, regional: CUP UnionPay) rides TLS between the
terminal (or the gateway-side processor) and the acquirer. Mutual
TLS is standard at the processor-to-acquirer leg; card-network
roots (Visa Transaction Security, Mastercard Encryption, Amex
Safekey) are RSA-2048+.

## Deployment footprint

- ~$5 trillion/year card-present transaction volume flows through
  these terminals (US + EU alone).
- US rollout mandated EMV liability shift 2015; Europe has had
  chip-and-PIN since early 2000s.
- India's UPI QR-code payments layer over POS terminals
  (mPOS/SoftPOS) — 500M+ active users.

## Breakage

A factoring attack against:

- **A terminal-vendor firmware-signing key** (Verifone, Ingenico,
  PAX): attacker signs a malicious firmware that the terminal's
  bootloader accepts. Every terminal of that vendor becomes a
  PAN-skimming device while still passing PCI PTS tamper-response
  checks. Precedent: multiple 2017-2022 incidents required
  physical tamper (Prilex) or supply-chain interdiction; a signed-
  firmware break removes both constraints.
- **An acquirer's RKI CA**: attacker injects known DUKPT BDK-
  derivations into any terminal in the estate; PINs flowing
  through are decryptable offline.
- **A card-network root** (Visa / Mastercard): cross-acquirer
  MITM of authorization traffic — forged approvals, transaction
  replay, chargeback manipulation.

Terminal firmware rotation is controlled by acquirers, quarterly
at best. A compromised signing key has a quarters-to-years fleet-
recovery window.
