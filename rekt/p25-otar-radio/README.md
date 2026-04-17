# Public-safety P25 / TETRA radio — OTAR key distribution, signed
# subscriber-unit firmware, KMF identity trust

Land Mobile Radio (LMR) serves police, fire, EMS, federal agents,
search-and-rescue, transit, utilities. Two dominant digital
standards:

- **Project 25 (P25)** — US standard (APCO P25 Phase 1 FDMA /
  Phase 2 TDMA). Used by ~90% of US public-safety agencies; DoD,
  DOJ, DHS, CBP, USSS also on P25. Vendors: **Motorola Solutions,
  L3Harris, JVCKenwood, BK Technologies**.
- **TETRA / TETRAPOL** — European + international equivalent.
  Used by UK Airwave, Germany BOSNet, Netherlands C2000, most
  EU police, Chinese MPS, Brazilian federal-police.

## RSA usage

### 1. OTAR (Over-the-Air-Rekeying) — KMF ↔ subscriber unit
The **Key Management Facility (KMF)** is the agency crypto master
that distributes Traffic Encryption Keys (TEKs) and Key Encryption
Keys (KEKs) to subscriber units. The symmetric-key material itself
is AES-256 (or legacy DES-OFB); but the OTAR delivery envelope
authenticates via an **RSA-backed identity chain** under TIA-102
Link-Layer Authentication (LLA, TIA-102.AACD) and per-unit
provisioning (TIA-102.AACE).

### 2. Subscriber-unit firmware signing
Motorola APX 6000 / 8000, L3Harris XL-200 / XG-100, JVCKenwood
NX-5000, BK Technologies KNG2 — every radio ships firmware signed
by the vendor HSM. Codeplug (per-unit configuration) is also
signed in FIPS-140-validated radios.

### 3. Identity authentication on the air (TIA-102 LLA)
TIA-102 Link-Layer Authentication authenticates each radio to the
system on registration. Uses challenge-response with a shared
secret — but the secret-provisioning path at the KMF uses an
RSA-backed CA.

### 4. FirstNet LTE / 5G public-safety PKI
The **FirstNet Band 14 network** (AT&T-operated US public-safety
LTE) issues cellular subscriber certs (eUICC, SIM-bound) through
an RSA-based PKI. Mission-critical push-to-talk (MCPTT, 3GPP TS
33.180) uses the same trust plane.

### 5. TETRA SCK / DMO provisioning and TAA1 protection
TETRA SCK (Static Cipher Key) and DMO (Direct Mode Operation) key
provisioning in TETRA-CENELEC conformant networks uses RSA-signed
key bundles distributed through the NMC (Network Management
Centre).

### 6. Console / dispatch-centre authentication
Motorola MCC 7500, L3Harris VIDA, Hexagon dispatch consoles sign
into the RFSS (RF SubSystem) with RSA-backed X.509 certificates.
Every dispatched talkgroup command carries an authentication chain.

### 7. Digital evidence / recording chain-of-custody
NICE NTR-X, Verint VPS, Voice Recording Systems — public-safety
call recorders sign recorded traffic for evidentiary admission in
court (cross-ref `axon-bodycam-evidence/`).

## Scale

- P25: ~6M subscriber units in service (North America)
- TETRA: ~4M units (Europe + international)
- FirstNet: ~5M devices (growing; includes body-worn cameras,
  in-vehicle modems, handhelds)
- Daily push-to-talk transactions across North American P25:
  ~1B+

## Breakage

A factoring attack against:

- **A KMF / subscriber-unit provisioning CA** (Motorola / L3Harris /
  JVCKenwood): attacker mints rogue subscriber-unit credentials,
  joins an agency's P25 network at will. With the RSA factored,
  key-wrap envelopes for OTAR can be intercepted and replayed or
  substituted — eventually the AES session keys themselves fall.
  Real-time interception of sensitive agency comms (FBI/CBP/DEA
  field operations, large-city PD tactical channels).
- **Vendor firmware-signing root**: signed firmware pushed fleet-
  wide that disables encryption, leaks keys in the clear, or
  bricks radios during a mass-casualty event. Public-safety
  radios failing during an active hurricane / mass-shooting /
  wildfire response is a life-safety scenario.
- **FirstNet subscriber CA**: impersonation of FirstNet-
  credentialed devices; MCPTT integrity compromise across the US
  public-safety mobile-broadband network.
- **TETRA NMC / TAA1 provisioning root**: equivalent impact for
  European public-safety comms; cross-border mutual-aid channels
  compromise.
- **Dispatch-console RFSS CA**: forged dispatch commands injected
  into operational talkgroups — false all-units calls, fabricated
  officer-down alerts, bogus mutual-aid requests. During an
  active incident this cascades into operational confusion that
  costs lives.

P25 / TETRA radio lifecycle: 10–15 years. A fleet-wide replace of
6M P25 radios runs ~$3,000–$8,000 per unit — tens of billions of
dollars in capital across every affected agency. The last time US
public-safety attempted a forced rekey at any scale was after the
Baltimore / New Orleans hurricane responses; it took years per
agency.
