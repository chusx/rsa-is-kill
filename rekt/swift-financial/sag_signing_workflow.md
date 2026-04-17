# SWIFT MT/MX message signing — where `swift_mtngs_rsa_signing.java`
# is actually invoked

SWIFT FIN (MT) and ISO 20022 (MX) payment messages flowing across
SWIFTNet carry LAU (Local Authentication) and PKI-signed envelopes
using RSA-2048 keys enrolled through SWIFT's HSM-resident PKI. The
primitive in `swift_mtngs_rsa_signing.java` is called by three
distinct tiers:

## 1. Customer connectivity: Alliance Access / SAG / Alliance Gateway

Every connected bank (11,000+ member institutions, every central
bank except a small handful of non-member states) runs:

  - **SWIFT Alliance Access (SAA)** — message store, MT parser,
    signing pipeline.
  - **SWIFT Alliance Gateway (SAG)** — network-edge proxy that
    speaks SWIFTNet protocol, HSM-backed RSA sign/verify.
  - **HSM**: Gemalto Luna SA-5 or Thales payShield, FIPS 140-2
    Level 3, holding the bank's SWIFTNet PKI private key.

Any MT103 customer credit transfer, MT202 financial institution
transfer, or ISO 20022 pacs.008 cross-border payment gets signed
server-side by `swift_mtngs_rsa_signing.java::signMessage` just
before it's emitted onto SWIFTNet.  The counterpart verify path
runs on the receiving bank's SAG.

## 2. SWIFT CSP (Customer Security Programme) controls

Post-2016-Bangladesh-Bank ($81M heist) SWIFT mandates:

  - Dual-control message approval with per-operator RSA smartcard
    (SWIFT-issued PKI token).
  - Signed nightly FIN Copy/MI-CV reconciliation batches.
  - PKI-signed firmware updates for SAA/SAG/HSM.

Every one of those gates is an RSA signature that SAG verifies.

## 3. MI-CV (Market Infrastructure Central Validation)

ECB TARGET2, T2S, CLS, CHIPS, Fedwire interchange sit at the edges
of SWIFTNet with their own signed-envelope requirements that SAG
multiplexes onto member-bank traffic. Cross-border wire settlement
for ~$5 trillion / day aggregates over RSA-signed envelopes.

## Operational workflow (ops-center boilerplate)

    # Nightly keystore sanity-check — SAG operator runbook
    SAG_HOME=/usr/swift/sag
    $SAG_HOME/bin/check-pkcs11 --hsm-slot=0 --pin=$HSM_PIN \
        --verify-key-usage signing,non_repudiation

    # Operator approval ceremony (dual-control)
    saa-cli submit --file mt103.batch \
                   --signer-1 alice.smartcard \
                   --signer-2 bob.smartcard
    # Each approval = an RSA signature over message hash; both
    # must be present before SAG emits to SWIFTNet.

    # Monthly PKI renewal campaign
    swift-pki renew --operator all --ca swift-root-2021 \
                    --notify risk@bank.example.com

## Breakage

A factoring attack against:

- **SWIFT's PKI root** (SWIFT Root CA): attacker mints an operator
  smartcard, a SAG node cert, and a member-bank institution cert,
  then injects MT103/pacs.008 messages that receiving banks see as
  genuinely issued by a named correspondent. The 2016 Bangladesh
  Bank attack required stealing operator credentials *plus*
  subverting SAA; a factoring break replaces both steps with a
  single cryptographic compromise.  $5T/day cross-border clearing
  is the blast radius ceiling.
- **An individual member bank's SWIFT RSA-2048 key**: targeted
  fraud authenticated as that bank.  Correspondent banks have
  recall / reversal mechanisms (stop-payment over MT192) but the
  delay window before detection is typically 24–72 hours for
  non-CLS-settled legs, which is sufficient for mule networks to
  move funds irreversibly.
- **The HSM firmware signing key** (Thales / Gemalto): attacker
  pushes a backdoored HSM firmware to member banks worldwide;
  every signed message thereafter is under attacker control even
  if the PKI roots themselves are intact.
