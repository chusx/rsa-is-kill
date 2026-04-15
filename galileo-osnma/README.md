# Galileo OSNMA — authenticated GNSS navigation messages

The EU's Galileo Global Navigation Satellite System operates the
Open Service Navigation Message Authentication (OSNMA) protocol,
live since July 2023 on E1-B. OSNMA protects civilian GNSS
receivers against spoofing attacks (e.g. faked GPS pushing a
vehicle, drone, or cargo ship off course) by cryptographically
authenticating the navigation message.

Two RSA layers sit at the root:

1. The **GSA (European Union Agency for the Space Programme) Merkle-
   tree root** is published in a **Merkle-Tree Public Key (MTPK)**
   file signed by the GSA Signing CA with an **RSA-3072** or
   **RSA-4096** key. Receivers fetch the MTPK file out-of-band
   (manufacturer provisioning, NAVCAST, firmware update) and pin
   the GSA CA public key in ROM/firmware.

2. The **TESLA (Timed Efficient Stream Loss-tolerant Authentication)
   root key** at the top of each OSNMA chain is itself signed by
   the GSA Signing CA in the DSM-PKR message (Digital Signature
   Message — Public Key Renewal). Receivers verify this RSA
   signature before trusting any TESLA MAC thereafter.

## Deployment

- Every OSNMA-capable receiver manufactured by u-blox (F9P, F10),
  Septentrio (mosaic-X5), Trimble, Hemisphere, NovAtel, STMicro
  (Teseo V), Broadcom (BCM47758 automotive GNSS), Qualcomm (SDX-
  series modems with GNSS cores) ships with the GSA CA pubkey
  baked in.
- Automotive Tier-1s integrate OSNMA receivers for anti-spoofing
  in ADAS + autonomous driving: Bosch, Continental, Aptiv, Denso.
- Aviation EGNOS augmentation + ground-based pseudolite PNT
  systems extend OSNMA into non-space-segment PNT.
- Maritime ECDIS (see `iho-s63-ecdis/`) increasingly fuses OSNMA
  position to detect AIS / GPS spoofing in Strait-of-Hormuz-type
  incidents.
- Critical-infrastructure timing (telecom BTS sync, smart-grid
  PMUs, financial-market MiFID II timestamping) migrating onto
  OSNMA for authenticated time.

## Breakage

A factoring attack against the **GSA Signing CA RSA key** lets an
attacker:

- Mint a rogue MTPK file that a victim receiver (during its next
  Merkle-tree key rollover) accepts as authoritative. From that
  moment on, attacker-controlled TESLA chains pass authentication.
- Mount a *cryptographically authenticated* GNSS spoof against
  every OSNMA-capable receiver in a region, pushing a ship onto
  rocks, sending a self-driving car across a lane boundary, or
  shifting a telecom-grid PMU timestamp by seconds — all with
  the receiver's OSNMA status LED showing green.

The GSA CA key is long-term (10-year rotation); compromise has no
fast revocation path for the installed base because MTPK updates
require either firmware pushes or NAVCAST broadcasts that take
weeks to reach every field receiver.
