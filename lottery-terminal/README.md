# State / national lottery terminals — signed wager + draw
# integrity

Lottery operators (state monopolies + national games) run tens of
thousands of retailer terminals that issue tickets and claim prizes.
Every wager, validation, and draw outcome is bound cryptographically.
A forged winning ticket or altered draw result costs the operator
directly; regulator trust and public confidence collapse on any
visible breach.

## Players

- **Operators**: IGT (PowerBall / Mega Millions back-end, many US
  states), Scientific Games / Light & Wonder, Intralot (Greek
  OPAP, many EU states), La Française des Jeux (FDJ), Camelot /
  Allwyn (UK National Lottery), Lottomatica (Italy), China
  Welfare Lottery
- **Terminal hardware**: IGT Altura / PhotonHD, SG WAVE, Intralot
  Photon
- **Draw machines**: RNG-based (certified) + mechanical (Halogen
  Smartplay). Both produce signed draw records.
- **Regulators**: MUSL (Multi-State Lottery Association — US
  PowerBall), NASPL, EL (European Lotteries), WLA (World Lottery
  Association, WLA-SCS:2020 security standard)

## RSA usage

### 1. Terminal-to-central wager signing
Every wager generated at a retailer terminal is signed with the
terminal's RSA key before transmission. Central system verifies
before the ticket is "registered" (becomes claimable). A bad
signature drops the wager; the retailer sees `COMMUNICATION ERROR`.

### 2. Central-to-terminal ticket-validation response
Prize-claim validation requests fetch a central-signed response
containing the ticket's prize tier and payout. Retailer-side
device verifies before paying out, preventing a man-in-the-middle
from inflating payouts.

### 3. Draw-result signing + publication
RNG output (for digital draws) or mechanical-draw adjudication
result is signed by the draw engine's HSM. Published to retailers
+ regulator + public audit site. WLA-SCS mandates independent
witness + cryptographic attestation of draw output.

### 4. Terminal firmware + game-DLL signing
Game logic (scratcher validation rules, Keno frequency tables,
Fast Play templates) is delivered as signed DLL / ELF bundles to
terminals. Regulator co-signs game logic approvals.

### 5. Inter-jurisdiction pool signing (PowerBall / EuroMillions)
Multi-state / multi-nation games combine sales feeds from
participating jurisdictions. Each jurisdiction's submitted sales
total is signed; the pooled jackpot calculation is signed by the
game's governing body (MUSL for PowerBall).

## Scale + stickiness

- US state lottery sales: ~$100B/year
- Global lottery gross sales: ~$300B/year
- Retailer terminals worldwide: ~1M+
- Regulatory certification: WLA-SCS:2020, ISO 27001, state gaming
  commissions — each cert covers a specific crypto architecture

Why RSA stays: terminal hardware has 7-10 year refresh cycles.
Game-logic DLLs are re-approved by state regulators; a crypto
change means re-submitting hundreds of game variants per state.
No lottery operator has announced a PQC migration timeline.

## Breakage

- **Central wager-signing root factored**: attacker forges ticket
  records after the draw ("pre-dated winning ticket" attack) —
  jackpot paid to attacker-controlled claim.
- **Draw-engine signing key factored**: forged draw-result bulletins
  — operator's published winning numbers rejected by retailers who
  trust the attacker's forged copy, or vice-versa. Regulatory
  standing evaporates.
- **Terminal firmware root factored**: rogue firmware validates
  counterfeit tickets locally — retailer-side fraud against
  operator at scale.
- **MUSL / EuroMillions pool-signing root factored**: jackpot-pool
  totals forgeable across jurisdictions — cross-border settlement
  disputes, game suspension.
