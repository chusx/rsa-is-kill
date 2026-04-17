# hdcp-2x-display — RSA-3072 in every HDMI 2.x / DisplayPort device

**Standard:** HDCP 2.2 / 2.3 Specification (Digital Content Protection LLC)
**Industry:** Consumer electronics — TVs, set-top boxes, game consoles, GPUs, Blu-ray
**Algorithm:** RSA-3072 (LLC signing key), RSA-1024 (device RSA private key for km exchange)

## What it does

HDCP (High-bandwidth Digital Content Protection) is the link-layer encryption between
a source (Blu-ray player, set-top box, PC GPU, console) and a sink (TV, monitor,
receiver). HDCP 2.x (HDMI 2.0+, DisplayPort 1.3+, MHL 3.0+) replaced the broken HDCP
1.x with an RSA-based authentication and key exchange.

The protocol (HDCP 2.x Authentication and Key Exchange, AKE):
1. Source reads the sink's `certrx` — a 522-byte certificate containing:
   - Receiver ID (5 bytes)
   - Sink's RSA-1024 public key (modulus + e=3)
   - Capability mask
   - DCP LLC RSA-3072 signature over the above
2. Source verifies the `certrx` signature using DCP LLC's RSA-3072 public key
   (burned into the source device at manufacture).
3. Source generates a 128-bit master key `km`, encrypts it with the sink's
   RSA-1024 public key (RSAES-OAEP-MGF1 SHA-256), sends to sink.
4. Both derive AES-128-CTR stream keys from `km` for video encryption.

The DCP LLC RSA-3072 root key signs every HDCP 2.x receiver certificate ever made.
Every HDCP 2.x source (essentially every TV, phone, tablet, console, GPU shipped
since ~2013) has this root key in its silicon.

## Why it's stuck

- The DCP LLC RSA-3072 public key is hardcoded in HDCP 2.x source-side silicon
  (a hardware block, usually in the display controller IP from Synopsys / Cadence).
  Replacing it requires a new silicon revision and flows through the entire
  HDMI/DisplayPort ecosystem.
- HDCP 2.3 (2018) is the latest revision and still uses RSA. There is no HDCP 3.x.
  DCP LLC publishes errata but has not announced a new signing algorithm.
- AACS (Blu-ray content protection) and HDCP are coupled: studios contractually
  require HDCP 2.2+ for 4K UHD content delivery. Breaking the chain means either
  studios pull 4K support or the content flows unprotected.
- Billions of deployed devices: every HDCP 2.x-capable TV, receiver, monitor,
  phone, tablet, console. TVs live 10-15 years in consumer homes.

## impact

HDCP 2.x is the link between content industry and display hardware. factor the DCP
LLC RSA-3072 root and you can mint infinite valid receiver certificates.

- factor DCP LLC's RSA-3072 root signing key. now you can issue `certrx` for a
  software "sink" of your choice. every HDCP 2.x source accepts your fake sink
  as legitimate, performs AKE, encrypts content to your chosen RSA-1024 key pair
  — which you generated, so you trivially decrypt. clean 4K HDR master of every
  UHD Blu-ray and 4K streaming session, directly off the HDMI pipe.
- HDCP 2.x receiver keys (RSA-1024) are in every real TV and receiver. factoring
  *any one* gives per-device content decryption. factoring an entire production
  run (from the manufacturer's key escrow) is worse.
- SRM (System Renewability Message): DCP LLC ships revocation lists signed with
  RSA-3072. a factoring attacker can forge SRMs to revoke specific Receiver IDs
  — denial-of-service bricking of target displays (imagine a stadium-wide
  broadcast source refusing every TV in a building).
- 4K streaming (Netflix/Disney+/Apple TV+) requires HDCP 2.2 for the UHD tier.
  a working attack collapses the whole "you can only stream 4K to a compliant
  display" model. clean 4K rips on release day, every release.
- corporate digital signage, stadium video walls, cinema alternate-content
  screenings, courtroom/classroom AV: all run on HDCP 2.x. decryption of any
  signal carried over HDMI.
- HDCP 2.2 "Repeater" authentication (AV receivers that sit between source and
  TV) uses the same RSA chain. a forged Repeater certificate lets an attacker
  MITM every HDMI chain.

## Code

`hdcp2_ake_rsa.c` — `hdcp2_verify_certrx()` (RSA-3072 signature verification over
receiver certificate with DCP LLC root public key), `hdcp2_encrypt_km()` (RSAES-OAEP
MGF1-SHA-256 encryption of 128-bit master key to sink's RSA-1024 public key),
`hdcp2_derive_ks()` (AES-128-CTR session key derivation from km).
DCP LLC root trust anchor and HDMI 2.x ecosystem context in comments.
