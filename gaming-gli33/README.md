# Casino gaming — GLI-33 signed firmware + RNG attestation

Slot machines, video lottery terminals (VLT), electronic table
games (ETG), and sports-betting kiosks deployed on every regulated
casino floor on the planet are certified against **Gaming Laboratories
International (GLI) standards**, principally:

- **GLI-11** — Electronic gaming devices
- **GLI-19** — Interactive gaming (online)
- **GLI-21** — Client-server gaming, Class III (Nevada-model)
- **GLI-26** — Wireless gaming
- **GLI-33** — Event wagering (sportsbook)

Every GLI-certified device stores a gaming binary hash in its
non-volatile state; at boot, the regulator (state gaming commission
or tribal gaming authority) can pull a **Self-Authentication Report**
to verify the running firmware matches the lab-certified hash. The
signatures are RSA-based.

## RSA dependencies

### 1. Firmware signing
IGT (International Game Technology), Aristocrat, Scientific
Games/Light & Wonder, Konami Gaming, Everi, AGS all sign game
binaries with RSA-2048 or RSA-4096 keys held in release HSMs. The
machine's secure bootloader (typically Bally Alpha 2 OS, IGT
Advantage OS, Konami SYNK OS) verifies the signature before
execution.

### 2. RNG attestation / GLI-11 §3.3
Random-number-generator modules are independently certified by
GLI. The RNG firmware hash is signed, and the regulator's audit
tool reads the signature from the machine and verifies against
the GLI-certified manifest.

### 3. Slot accounting system / SAS / G2S / S2S
**SAS** (Slot Accounting System) is the legacy protocol; **G2S**
(Game-to-System) and **S2S** (System-to-System) are the GSA
successors. G2S messages (meters, events, jackpot
authorizations) ride over TLS with mutual cert auth. Jackpot
adjudication above the IRS W-2G threshold ($1200) requires
digitally signed event logs — RSA all the way.

### 4. Sportsbook event wagering (GLI-33)
Sportsbook platforms (DraftKings, FanDuel, BetMGM, Caesars,
BetRivers, Hard Rock Bet) sign every bet slip and settlement
record with the operator's RSA key for regulator audit (New
Jersey DGE, Nevada GCB, UK GC, Gibraltar, Malta MGA).

### 5. EGM-to-cashless / TITO (ticket-in/ticket-out)
Ticket printers emit barcoded slips whose redemption at cashless
kiosks is validated by cross-referencing the central cashless
server's signed ticket record — RSA-signed TITO tickets prevent
counterfeit redemption. Major vendors: IGT TITO, Konami Cashless,
Everi Cash Club.

### 6. Regulator tooling
GLI's own audit tools (GLI-Certify, SANS — Slot Analysis and
Notification System) and state gaming commission field-audit
appliances (Nevada GCB, New Jersey DGE, Michigan MGCB) verify
signatures chain to the lab-issued root.

## Scale

- ~8.6 million gaming machines worldwide (slots + VLT)
- US commercial + tribal gaming revenue ~$70B/year
- 30+ US states + ~100 countries operate regulated gaming under
  GLI-based rules

## Breakage

A factoring attack against:

- **An OEM game-signing CA** (IGT, Aristocrat, Light & Wonder):
  attacker signs a firmware with altered payout curves (e.g.
  return-to-player lowered from 92% to 88% on a specific title),
  distributed as a legitimate OEM update; the lab-certified hash
  is bypassed because the regulator's audit tool validates only
  the signature. Multi-billion-dollar house-edge manipulation
  potential across fleet.
- **GLI's own certification signing key**: attacker forges lab-
  certification manifests; regulator audit tools accept
  attacker-chosen firmware as "GLI-certified" at any operator.
- **Operator sportsbook RSA key**: attacker forges bet-slip
  records; bankroll reconciliation and regulatory audit evidence
  chain falsified.
- **State gaming commission PKI**: attacker forges state-issued
  machine approvals, registration certificates (the EIN-bound
  cert that authorizes a specific serial on a specific floor).

Gaming regulators typically mandate firmware recertification on
any material change — multi-month process per game title. A
factoring compromise cleanup is a ~2-year operational program per
affected OEM + jurisdiction.
