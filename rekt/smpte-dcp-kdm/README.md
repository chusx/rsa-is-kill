# Digital Cinema — SMPTE DCP / KDM delivery to theatrical projectors

Every feature film distributed to cinemas since ~2012 ships as a
**Digital Cinema Package (DCP)** conformant to **SMPTE ST 429** /
**ISDCF** standards, encrypted under per-playlist AES keys that
are delivered to each projector via a **Key Delivery Message (KDM)**
signed + encrypted with the projector's **Security Manager (SM)**
certificate.

## Players

- **Projector / media-server vendors**: Christie, Barco, NEC,
  GDC Technology, Dolby, Qube Cinema, Doremi (acquired by Dolby),
  Sony Digital Cinema
- **Studios / distributors**: every major (Disney/Buena Vista,
  WB, Universal, Paramount, Sony Pictures, Lionsgate, A24, etc)
  + indie distributors worldwide
- **Key-distribution / lab services**: Deluxe, Technicolor, Qube
  Wire, GDC, BYDeluxe

## RSA usage

### 1. Projector Security Manager certificate
Each SMPTE-compliant projector / Integrated Media Block (IMB) has
a factory-installed RSA-2048 key pair in a tamper-responding
enclosure (FIPS 140-2 Level 3). Cert chain terminates at the
vendor root. Public cert is published to booking / KDM services.

### 2. KDM — per-show key envelope
Studio lab generates one KDM per (projector, playlist, engagement
window). KDM is an XML structure with a CPL (Composition Playlist)
reference, a window (e.g. "2024-07-04 17:00 through 2024-07-06
02:00"), and the per-reel AES-128 keys encrypted under the
projector's RSA public key (RSA-OAEP-SHA1 / -SHA256). Signed with
the distributor DKDM-signing key.

### 3. DCP content signing
The CPL, PKL (Packing List), and ASSETMAP each carry XMLDSig RSA
signatures from the DCP's originating facility. Exhibitor-side
verification confirms the package is authentic + not modified
in transit.

### 4. Trusted Device List (TDL)
Studios maintain a TDL — projectors authorised to play. Revoked
projectors (stolen, decommissioned, key extracted) are pulled
from the TDL so fresh KDMs won't include them.

### 5. Forensic watermarking keys
Dolby, Philips, NexGuard — forensic watermark seeding uses signed
keying material delivered into the projector to tag pirated copies
back to the leaking screening.

## Scale + stickiness

- ~200,000 SMPTE digital-cinema projectors worldwide
- ~20,000 new DCP titles / year across global exhibition
- Projector lifecycle: 10–15 years; IMB security modules have
  time-limited cert validity (~15–20 years from manufacture;
  after expiry the projector is unusable for new KDMs)

Why RSA is sticky: **every projector's factory-installed cert is
immutable.** Replacing a cert requires physical service on the
Security Manager (in-situ re-certification or Security Module
swap). The installed base was built entirely on RSA; ECC support
was not mandated in ST 429 until late revisions, and distribution
trust relationships remain RSA-centric.

## Breakage

- **Studio DKDM-signing root factored**: attacker issues KDMs for
  any projector on the TDL, enabling playback of any licensed
  title at any venue at any time. Zero-day worldwide piracy
  baseline — content goes from theatrical-window-only to
  in-the-wild the same day.
- **Vendor Security-Manager CA factored** (Christie / Barco / NEC
  / Dolby / GDC): attacker mints cert for a fake projector,
  receives KDMs, extracts AES keys in the clear. Clean pirate
  copies of every first-run film immediately.
- **Distributor content-signing key factored**: attacker
  substitutes the feature with alternate content (propaganda,
  malware-laden trailers); exhibitor playback rules accept the
  swap because the signature chains validly.
- **TDL signing key factored**: revoked / stolen projectors
  rejoin the trusted pool — old extracted keys re-usable.

DCI-mandated Security Manager re-certification at scale is without
precedent; major studio cooperation + every vendor's field-service
footprint would be required for a crypto rotation.
