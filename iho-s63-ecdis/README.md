# iho-s63-ecdis — RSA in SOLAS-mandated electronic nautical charts

**Standard:** IHO S-63 Data Protection Scheme (International Hydrographic Organization)
**Industry:** Maritime navigation — every SOLAS-regulated ship worldwide
**Algorithm:** RSA-1024 (IHB scheme administrator key), RSA-1024/2048 (data server keys)

## What it does

SOLAS V/19 requires every commercial ship over 500 GT and every passenger ship on
international voyages to carry ECDIS (Electronic Chart Display and Information System).
ECDIS accepts only ENCs (Electronic Navigational Charts) produced under IHO S-57/S-101.
S-63 is the copy-protection and authentication scheme layered on top.

The trust chain:
- IHO's International Hydrographic Bureau (IHB) holds the scheme administrator RSA key.
- Data Servers (UKHO, NOAA, Primar, C-MAP, etc.) submit their RSA public keys to IHB
  and receive IHB-signed Data Server Certificates (X509-like structure defined in S-63
  Annex B, but S-63 predates modern X.509 profiles).
- Each ENC cell is distributed encrypted with a cell key (Blowfish/DES in legacy, now
  AES in S-63 Edition 1.2). The cell key is delivered in a "permit" file.
- Permits are signed with the Data Server's RSA key. ECDIS verifies the permit signature
  against the IHB-signed Data Server Certificate.

Every ECDIS on every SOLAS ship has the IHB public key hardcoded in the install. Chart
updates arrive weekly via CD, USB, or satellite download. Permit signatures are verified
before the chart is decrypted and displayed on the bridge.

## Why it's stuck

- S-63 Edition 1.2 (2015) still specifies RSA-1024 for the scheme administrator key and
  allows RSA-1024 for data server keys. There is no IHO work item to replace RSA.
- ECDIS is type-approved by flag states under IMO MSC.232(82). Changing the crypto
  primitive requires re-type-approval of every ECDIS model from every manufacturer
  (Furuno, JRC, Raytheon Anschütz, Kongsberg, Wärtsilä SAM, Transas). Each re-approval
  is a multi-year process with IACS class societies.
- Ships run ECDIS on Windows XP/7/10 embedded that may not be updated for the life of
  the vessel (20-30 years). Firmware updates via satellite are bandwidth-constrained.
- The IHB distributes the scheme administrator public key via a certificate file named
  `IHO.CRT` that ships on every ECDIS. Any replacement requires a coordinated rollout
  across every ECDIS install worldwide — there's no online trust store.

## impact

ECDIS is how the bridge crew sees where the ship is. if the chart is forged, the ship
goes where the attacker wants — including into rocks.

- factor the IHB scheme administrator RSA-1024 key (it's embedded in every ECDIS as
  `IHO.CRT`, retrievable from any installation). forge a Data Server Certificate.
  now you can sign arbitrary ENC permits that every SOLAS ECDIS will accept.
- forge ENC updates that shift depth contours, move buoys, delete wrecks from charts,
  or add phantom shoals. the bridge watch officer trusts the displayed chart absolutely
  — S-63 authentication IS the chain of custody. ECDIS has no "second source" check.
- targeted attack: forge a permit for a specific vessel's voyage, served via the
  ship's chart distribution service (most use automated email or satellite pull).
  crew installs the update at sea, heading changes on autopilot are now routed
  through modified chart features.
- Suez Canal, Strait of Malacca, Singapore Strait, English Channel — high-density
  traffic lanes where a single grounding blocks the passage. Ever Given (2021) cost
  $10B+ in trade disruption from a single unintentional grounding.
- warship navigation: naval ECDIS (ECDIS-N, STANAG 4564) uses the same S-63 trust
  anchor. factor the IHB key, feed forged chart data to a warship's bridge system.
- regulatory: IMO has no fallback. a flag state that cannot trust its ECDIS charts
  has no compliant navigation path for SOLAS vessels. the entire system would
  need to revert to paper charts, which commercial fleets no longer carry.

## Code

`s63_permit_verify.c` — `s63_verify_data_server_cert()` (verify IHB RSA-1024 signature
on data server certificate), `s63_verify_permit()` (verify RSA signature on cell permit,
extract AES cell key), `s63_decrypt_cell()` (AES decrypt ENC cell using recovered key).
SOLAS compliance context and IHB trust anchor model in comments.
