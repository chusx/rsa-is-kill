# ATM XFS firmware & remote key loading

ATMs (Automated Teller Machines) run a layered stack standardized
around **CEN/XFS** (Extensions for Financial Services, EN 1546-series).
Major vendors: **Diebold Nixdorf** (ProCash, DN Series, Vynamic Security),
**NCR Atleos** (SelfServ, Edge), **Hyosung**, **GRG Banking**,
**Wincor Nixdorf** (pre-merger).  Deployed: ~3 million ATMs globally.

Three RSA-dependent subsystems:

## 1. Signed-firmware updates
Every host-PC image, BIOS, BIOS-level boot guard, XFS SP (Service
Provider) driver, and firmware for subcomponents (CDM — Cash Dispenser
Module; EPP — Encrypting PIN Pad; card reader; receipt printer) is
RSA-signed by the vendor's release HSM. RSA-2048 or RSA-4096 keys.
Both Diebold's "Vynamic Security" and NCR's "Solidcore / Carbon Black
application control" enforce signature verification before execution.

## 2. Remote Key Loading (RKL) — TR-34
**ANSI X9 TR-34** and its predecessor **X9.24-2** define the standard
for remotely loading PIN-encryption keys (TMK — Terminal Master Key)
into an ATM's EPP over the wire.  The key-transport protocol is a
CMS-based exchange where:

- The ATM EPP generates an RSA-2048 keypair at manufacturing and
  holds the private half in tamper-responsive hardware.
- The bank's Key Distribution Host (HSM, typically Thales payShield
  or Futurex Excrypt) presents a CA-signed cert binding that pubkey
  to the ATM serial.
- Host sends an RSA-OAEP-wrapped TMK to the ATM.
- ATM EPP unwraps with its RSA private key, installs the TMK,
  derives session keys for PIN-block encryption under TDES/AES.

## 3. Acquirer / processor comms
ATM-to-switch communications to the card-network (Visa VisaNet,
Mastercard Banknet, regional: Pulse, NYCE, Interac, STAR, Link UK,
LCH-Regis) ride over TLS 1.2+ with mutual cert auth. Every ISO 8583
financial message flowing over that tunnel is under an RSA
handshake.

## Deployment scale

- US: Cardtronics (now Allpoint / Payment Alliance), Bank of America
  (~16k ATMs), JPMC (~17k), Wells Fargo (~13k).
- Europe: LINK (UK), Euronet Worldwide (pan-EU), Deutsche Bank,
  BNP Paribas.
- Asia: Japan's Seven Bank (~26k standalone ATMs in 7-Eleven),
  India's Tata Communications Payment Solutions (~20k).
- Latin America: B3, Prosegur Cash, Banco do Brasil (~14k).

## Breakage

Factoring attack against:

- **Diebold or NCR firmware-signing root**: attacker distributes
  a malicious firmware image (jackpotting payload) that every
  ATM of that vendor accepts. Precedent: 2010s-era Ploutus, 2020
  "black-box jackpotting" attacks required physical USB access —
  a signed-firmware path lets the payload ride the vendor's own
  OTA update channel. Mass cash-out attack.
- **Bank / processor RKL root CA** (the CA that signs TR-34 KTK
  certs): attacker mints a Key Distribution Host cert, establishes
  TR-34 session with any ATM in the estate, injects a known TMK,
  then decrypts PIN blocks flowing through that ATM in real time
  — wholesale PIN harvesting.
- **Per-ATM EPP key**: targeted break of one ATM's PIN protection;
  lets attacker decrypt historically-captured PIN blocks for that
  specific ATM.
- **Card-network acquirer TLS root**: MITM of ISO 8583 flows;
  authorization decisions, chargeback data, all forgeable.

ATM firmware rotation is months-to-years. RKL certs are rotated
annually at best. A factoring break has a window measured in
fleet-refresh timescales before remediation completes.
