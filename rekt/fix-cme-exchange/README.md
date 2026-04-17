# FIX over TLS / SFTI / Secure FIX — exchange co-location, order
# entry signing, market-data integrity

The global equities, futures, options, and FX markets run on the
**FIX (Financial Information Exchange) protocol** between broker-
dealers, exchanges, ECNs, and clearing houses. Approximate daily
notional: **$500 trillion** across FX, fixed-income, and
derivatives markets globally.

## Venues

- **CME Group** (CME / CBOT / NYMEX / COMEX) — iLink 3 order entry
- **ICE (Intercontinental Exchange)** — ICE Messaging / FIX
- **NASDAQ** — OUCH / ITCH + FIX
- **NYSE / ARCA / AMEX** (ICE-owned)
- **Cboe** (BZX / BYX / EDGX / EDGA + European Cboe)
- **LSEG** (London Stock Exchange / Turquoise / FXall)
- **Eurex / Deutsche Börse, SIX, Euronext, ASX, JPX, HKEX, SGX,
  BSE / NSE, B3 Brasil, TMX Toronto**
- **Dark pools** — Liquidnet, Virtu MatchIT, IEX

## RSA usage

### 1. TLS / mutual auth on order-entry and market-data
Every non-co-located FIX session terminates on TLS with mutual
auth. Co-located dark-fibre sessions inside the exchange cage
are sometimes clear (the exchange justifies absence of TLS on a
physical-security argument) but moving towards TLS end-to-end.
Per-participant client RSA certs bind to the exchange member ID.

### 2. Exchange message-signing initiatives
**CME iLink 3** has introduced per-message signatures on certain
control messages. **Nasdaq Nordic** uses RSA-based per-session
auth tokens. **LSE Millennium Exchange** uses TLS + client certs
with optional order-signing.

### 3. Clearing-house margining messages
DTCC, Options Clearing Corporation (OCC), CME Clearing, LCH,
Eurex Clearing all exchange signed margin calls and end-of-day
settlement messages with member firms over **SWIFT FIN** (see
`swift-financial/`) plus vendor ISV links — RSA-signed.

### 4. Market-data integrity (consolidated tape)
SIP (Securities Information Processor) — the consolidated-tape
vendor in the US — relies on exchange inputs whose integrity is
trust-anchored in exchange-operator PKI. Primary-listing-exchange
fallback (NYSE for NYSE-listed, Nasdaq for Nasdaq-listed)
exchanges signed NBBO contributions.

### 5. Exchange co-location / SFTI signing
**SIAC SFTI (Secure Financial Transaction Infrastructure)** is the
MPLS/Ethernet connectivity carrier between exchanges and member
firms. SFTI endpoints authenticate with RSA X.509.

### 6. Post-trade regulatory reporting
MiFID II RTS 27/28, SEC CAT (Consolidated Audit Trail), FINRA
OATS-successor reports — member firms sign the reports with RSA
keys bound to their firm's CRD / LEI.

### 7. Risk-control gate signing ("big red button")
SEC Rule 15c3-5 requires broker-dealers to have pre-trade risk
controls. Kill-switch commands from the broker risk-management
desk to the order-entry gateway are signed so that a compromised
order engine cannot ignore a kill request.

## Scale

- CME Globex handles ~30M messages/day steady-state, peaks >1B/day
- Options order messages (US OPRA feed): ~100B/day at market open
- Dollar throughput of global FX (~$7.5T/day per BIS Triennial)
  moves through FIX-adjacent rails
- Dodd-Frank swap execution facilities (SEFs) report trade data
  with RSA-signed submissions to SDRs (Swap Data Repositories)

## Breakage

A factoring attack against:

- **An exchange member client-CA**: attacker impersonates a member
  firm, submits orders on their behalf. Market manipulation at
  industrial scale — signed orders to move a security pre-
  announcement, spoof the book, layer the OPRA feed. SEC/CFTC
  enforcement trail would reach the member firm whose key is
  factored.
- **A clearing-house member-signing root (DTCC/OCC/CME Clearing/
  LCH)**: forged variation-margin calls or forged settlement
  instructions. A bad settlement signal during a stressed day
  could trigger an unwind cascade — 2008-class systemic event.
- **An SFTI / exchange-peer CA**: attacker injects false tape
  contributions into the consolidated market data; algos trade
  on poisoned prices globally.
- **A CAT / regulatory-reporting root**: historical audit trail
  loses integrity — years of SEC enforcement cases that relied
  on CAT evidence are open to re-examination.
- **A broker 15c3-5 kill-switch signing key**: attacker blocks
  the broker from killing their own runaway order-flow during
  an incident. Amplifies a Knight-Capital-class event by
  preventing the broker from stopping the bleeding.

Exchange connectivity + PKI lifecycle: 5–10 years per key,
relatively frequent by industry standards — but a systemic
factoring break requires coordinated rotation across every
member firm and vendor ISV, touching thousands of trading
desks globally. Regulators would likely halt trading on affected
venues until trust is re-established — multi-day market closures
were last seen at this scale only after 9/11.
