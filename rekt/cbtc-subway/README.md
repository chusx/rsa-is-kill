# Urban transit Communications-Based Train Control (CBTC) —
# signed movement authority, trackside object controllers

Metro / light-rail / airport-people-mover systems use **CBTC**
instead of mainline-railroad PTC. CBTC is IEEE 1474 / IEC 62290
compliant and enables "moving-block" signaling with short train
separation. ~200 deployed CBTC lines worldwide, many recent:

- **Thales SelTrac** — Toronto TTC, Shanghai, Singapore, NYC
  MTA L/7/Canarsie, Hong Kong, London DLR, Vancouver SkyTrain
- **Siemens Trainguard MT** — Paris M14, Budapest M4, Oslo,
  NYC Queens Blvd, Barcelona L9/L10
- **Alstom Urbalis** — London Jubilee/Victoria/Northern, São
  Paulo, Panama City, Dubai Metro
- **Hitachi Rail STS BlueSigns** — Rome, Milan
- **Wabtec CBTC** — ex-Bombardier lines post-acquisition
- **Ansaldo / Hitachi** — Copenhagen, Naples, Riyadh
- **CRRC + CASCO** — Chinese operators

Railway SIL 4 safety certification under EN 50129 / EN 50128 /
IEC 61508.

## RSA usage

### 1. Train-borne ATP/ATO controller firmware signing
Every onboard ATP (Automatic Train Protection) + ATO (Automatic
Train Operation) unit runs signed firmware (Thales SelTrac S40,
Siemens Trainguard MT SW3, Alstom Urbalis 400). Safety-rated
firmware ships with vendor RSA sigs counter-signed by the
operator's SI (systems integrator) in some deployments.

### 2. Wayside Object Controller (WOC / ZC) authenticated messaging
Zone Controllers, Interlocking Controllers, Signal Controllers,
Point Machine Controllers communicate with trains + with each
other over a LAN with RFC 3711 SRTP or vendor-specific auth.
Message origin authentication rides RSA certs binding each
wayside asset.

### 3. Movement-authority generation
Zone Controller computes movement authority (MA) for each
train and issues it as a signed datagram. Train's ATP refuses
unsigned / stale / wrongly-sequenced MAs.

### 4. Control-centre dispatch authorisation
Operations Control Centre (OCC) commands — route setting,
emergency stop broadcast, degraded-mode mode switch — carry
dispatcher signatures from the OCC's HSM-backed CA.

### 5. Signalling + field-level-integration PKI
Modern projects deploy a signalling PKI per line / per system
(e.g. Crossrail / Elizabeth Line, MTR Hong Kong, Paris RATP)
covering: train ↔ wayside, wayside ↔ wayside, OCC ↔ all
assets.

## Scale + stickiness

- ~200 CBTC metro lines; ~20,000 CBTC-equipped cars
- Major urban-transit modernisations: NYC MTA CBTC rollout
  across the system is a $7B+ multi-decade programme
- Railway safety-case lifecycle: 30+ years
- Re-certification under EN 50129 after any cryptographic
  architecture change: 6–18 months per line

Why RSA is sticky: SIL-4 safety-case lock-in is severe.
Vendors cannot swap crypto primitives without re-opening the
safety dossier with ISA (Independent Safety Assessor). Most
CBTC programmes deployed 2010–2024 are RSA-anchored and in
service for 2040+.

## Breakage

- **Vendor ATP/ATO fw root factored**: signed firmware fleet-
  wide that disables protection logic or subtly re-tunes
  stopping distances. SIL-4 case collapses per IEC 61508;
  operators forced into degraded manual ("Line of Sight")
  operation until re-certified — throughput collapses in
  dense urban systems (the NYC L train at capacity requires
  CBTC headways; manual blocks can't approach them).
- **Zone Controller MA-signing root factored**: attacker
  injects forged MAs — moving blocks overlap, trains
  commanded to speeds above track limits, platform-arrival
  positions mis-set. Station over-run or in-tunnel collision
  between platooned trains.
- **OCC dispatcher CA factored**: forged emergency-stop /
  mode-switch commands. DoS against entire line at peak —
  300,000 stranded passengers per hour on a major metro.
- **Signalling PKI root factored**: wayside-to-wayside
  handshakes compromised; route-setting integrity lost.
