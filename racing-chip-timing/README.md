# Professional race timing — ChampionChip / MYLAPS / RFID +
# signed finish records for prize money + records

Professional cycling (UCI), road running (World Athletics AIMS-
certified marathons), triathlon (Ironman / WTCS), motorsport
(MotoGP / F1 support / Indy), alpine ski (FIS), and speed skating
all run on **transponder-based timing** whose official results
are signed at the finish-line computer and propagated to
federations, sponsors, and anti-doping bodies. A Boston Marathon
Abbott World Majors finish or a UCI stage-win affects prize money,
record ratification, sponsor bonus clauses, and anti-doping
sample assignment.

## Players

- **Timing providers**: MYLAPS (Tissot partner), Race Result AG,
  Chronelec (LEMAN), Ipico Sports, ChronoTrack (IPICO Inc),
  J-Chip, Tag Heuer Chronelec, Omega (IOC / Olympic), Al Kamel
  (MotoGP / F1 support), AMB / TrakMate, Longines (FIS alpine +
  equestrian)
- **Federations**: UCI, World Athletics, World Triathlon, FIM,
  FIA, FIS, ISU, AIMS (marathons), Abbott World Marathon Majors
- **Anti-doping pairing**: WADA ADAMS — signed finish positions
  feed target-test pool selection
- **Marathon-series sponsors**: Abbott (WMM), TCS (London, NYC
  sponsor), Bank of America (Chicago), BMW (Berlin)

## RSA usage

### 1. Finish-line read → signed result
Each transponder-read at the finish line (decoder: MYLAPS BibTag,
Race Result USB Timing Box) produces a signed record binding bib
number + transponder ID + crossing timestamp + chip-time + gun-
time + decoder serial. Athlete's legal-of-record time.

### 2. Stage / split signing for multi-stage events
Tour de France / Giro / Vuelta stage finishes + intermediate
sprints + KOM / hot-spot primes are signed separately. GC
calculation and podium depend on the chain.

### 3. World / course record ratification
World Athletics requires signed splits from IAAF-approved timing
for world-record ratification. A signed timing-provider export is
the record-ratification evidentiary substrate.

### 4. Anti-doping test pool signing
WADA's post-race test-subject selection (automatic top-N + random)
draws from signed finish lists. ADAMS ingests the finish
manifest and pairs to chaperone-collection records.

### 5. Transponder-provenance signing
Rental transponders (marathon fields with 30,000+ athletes) carry
provenance signed by timing-provider at issue + return. Prevents
substitution attacks (paying a professional pacer to wear an
amateur's bib).

### 6. Prize-money + sponsor-bonus disbursement signing
Athletes' contracts carry sponsor-bonus triggers (sub-2-hour
marathon, stage-win, podium). Bonus disbursement against a
signed finish-record closes the payment chain.

## Scale + stickiness

- Global marathons/year with chip timing: ~5,000
- Tour de France: ~50 timing points/stage × 21 stages
- Professional cycling prize money: ~€20M+/year UCI tour events
- Record-ratification: a single 1%-off signature-chain failure
  invalidates history records

Why RSA stays: timing-provider firmware + federation-issued
approvals pin specific cryptographic profiles. World Athletics
Rule 260 + UCI Regulations reference timing-supplier certification.
Any algorithm rotation touches certified decoders at every
provider; re-certification is per-federation.

## Breakage

- **Timing-provider decoder signing key factored**: forged finish
  times fabricated for prize money / record ratification /
  sponsor bonus. Marathon-course records vacated retroactively.
- **UCI / World-Athletics ratification signing factored**:
  bona-fide records become uncertifiable; federation audit
  posture collapses, sponsors withhold bonuses.
- **WADA ADAMS finish-list signing factored**: post-race test
  pool selection corruptible — doper avoids testing through
  forged "missed top-10" attribution.
- **Transponder-provenance signing factored**: bib-substitution
  fraud at scale in mass-participation events — professional
  pacers collect amateur prize money (Rosie Ruiz-style).
