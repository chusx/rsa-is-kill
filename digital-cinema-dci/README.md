# digital-cinema-dci — RSA in every commercial movie theater (DCI/SMPTE)

**Standard:** DCI Digital Cinema System Specification; SMPTE ST 430-1, 430-2, 430-3
**Industry:** Motion picture exhibition — Disney, Universal, Warner, Sony, Paramount
**Algorithm:** RSA-2048 (KDM Recipient Certificate, Content Key wrapping via RSAES-OAEP)

## What it does

Every Hollywood feature film released since ~2012 ships to cinemas as a DCP (Digital
Cinema Package) — encrypted MXF files on a physical drive or delivered via satellite/
fiber. The content is AES-128-CBC encrypted at the frame level. To play it, the
projection server needs the AES content keys, which are delivered in a KDM (Key Delivery
Message, SMPTE ST 430-1).

Each KDM is:
- Addressed to exactly one projector (by its RSA-2048 device certificate thumbprint)
- Valid for a specific time window (the booking window for that screening)
- Encrypted to that projector's RSA-2048 public key via RSAES-OAEP (wraps the AES keys)
- Signed by the studio's Distribution KDM Generator (DKDM) using RSA-2048 XMLDSig

Every DCI-compliant projector (NEC, Christie, Barco, Sony) has an embedded RSA-2048
keypair burned in at manufacture, with the public key certified by the manufacturer's
CA, which chains to the DCI Trusted Device List or a studio-accepted root.

## Why it's stuck

- DCI specification is maintained by the DCI consortium (the six major studios).
  Changing the KDM format requires consensus from all DCI members plus coordinated
  firmware updates to every DCI projector worldwide (~150,000 screens).
- SMPTE ST 430-1:2006 (updated 2010) hardcodes RSA and RSAES-OAEP-MGF1. There is
  no successor standard in active development.
- Projector Security Manager (SM) modules are FIPS 140-2 Level 3 tamper-resistant
  hardware. The RSA keypair is generated inside the SM and cannot be replaced —
  the projector's identity IS that keypair. Moving off RSA means replacing the
  Security Manager module in every projector, which is a hardware swap, not firmware.
- The DCI Compliance Test Plan certifies each projector model. Any crypto change
  requires re-certification.

## impact

DCI KDMs are what gates piracy. forge the KDM signing chain and you can issue valid
KDMs for any film to any projector — but more usefully, factor any projector's
RSA key and you can decrypt any KDM sent to it.

- factor a cinema Security Manager's RSA-2048 key (projector public key is routinely
  exchanged via Trusted Device List CSV files, emailed between bookers and distributors
  — the public key is not a secret). now the KDMs for every film shown on that projector
  decrypt to you. access to content keys = plaintext DCP = clean pirate master for
  every film that screened, including pre-release screeners.
- forge KDM signing: factor a studio DKDM-generator key and issue KDMs for films
  that weren't released to a given venue. projector accepts, plays the film.
- the "Distribution KDM" (DKDM) used between studios, distributors, and labs also
  chains to RSA. intercepted DKDMs from a compromised studio distribution CA let an
  attacker intercept and re-encrypt content for their own projector.
- Goldilocks zone for film piracy: current DRM keeps clean masters off the net.
  a projector-key factorization attack produces 4K DCI-grade rips of every major
  release, invalidating the whole post-2012 anti-piracy model.
- independent / art-house cinemas share a FIPS-weak projector pool globally. some
  older Dolby / Doremi / GDC SM modules had design weaknesses already; adding a
  classical factoring break collapses the fleet.

## Code

`dcdm_kdm_rsa.py` — `parse_kdm_xml()` (extract CipherValue and Signature), `unwrap_content_keys()`
(RSAES-OAEP decrypt the AES-128 content key block), `verify_kdm_signature()` (XMLDSig
RSA-2048 verify against studio's KDM generator cert). DCI projector RSA trust model and
DKDM context in comments.
