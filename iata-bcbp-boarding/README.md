# iata-bcbp-boarding — RSA in signed airline boarding passes (IATA BCBP)

**Standard:** IATA Resolution 792 — Bar Coded Boarding Pass (BCBP); IATA PADIS EDIFACT
**Industry:** Commercial aviation — ~4 billion boarding passes issued per year
**Algorithm:** RSA-1024 (legacy) / RSA-2048 (current) — digital signature over PECTAB M, N, O fields

## What it does

Every commercial boarding pass worldwide — paper, mobile wallet, Apple/Google Wallet —
encodes passenger data in the IATA BCBP format (Resolution 792). The PDF417 barcode or
Aztec 2D barcode contains:

- Mandatory fields (M1): name, PNR, origin, destination, flight number, date, class,
  seat, check-in sequence
- Conditional fields (C1-C9): frequent flyer number, bag tag, TSA PreCheck indicator,
  document verification data
- **Security fields (M, N, O)**: digital signature fields for issuer authentication

The Security Data is an RSA signature over the BCBP mandatory and conditional items,
using a key identified by the `Version Number` + `Type of Security Data` + `Size of
Security Data` header fields. Each issuing airline maintains its own RSA keypair and
distributes public keys via IATA's Key Signing Authority (KSA) bulletin.

Use cases of the signature:
- **Airport security**: TSA/CBP (US), BPA (UK), BPS (EU) scan boarding passes at
  checkpoints and verify the airline's signature as part of TSA Secure Flight /
  APIS verification
- **TSA PreCheck**: the PreCheck indicator on the BCBP is signed by the airline;
  TSA lane scanners verify the signature before routing passengers to PreCheck lanes
- **Self-boarding gates**: Air France, KLM, Lufthansa, and most Asian carriers use
  automated boarding gates that scan and verify the signed BCBP
- **Mobile wallet pass verification**: Apple Wallet and Google Wallet verify airline
  signatures on updates (flight status, gate change pushes)

## Why it's stuck

- IATA Resolution 792 was last revised in 2023 and still specifies RSA-1024/2048
  with SHA-1 (legacy) or SHA-256 (current). No working group is drafting a post-RSA
  successor.
- Boarding pass verification runs on a mix of TSA CAT-2 / CBP e-gate readers,
  airline self-boarding gates (Vision-Box, Materna, SITA), and PDA handheld scanners
  at airports. Each has its own firmware update cycle, vendor trust store, and
  certification regime.
- The IATA Key Signing Authority is a trusted third party that distributes airline
  public keys. No PQC successor has been announced by IATA.
- Airlines rotate BCBP signing keys every 3-5 years. Each rotation requires the
  airline to upload a new public key to IATA KSA and wait for dissemination to
  all scanner endpoints (DCS systems, airport lounges, partner airlines for
  interline boarding passes).

## impact

the boarding pass signature is the only authenticated binding between a passenger
and a seat, between a passenger and Secure Flight vetting, between a passenger and
the sterile area of an airport. forge the signature and you forge airport access.

- factor an airline's BCBP RSA signing key (distributed publicly via IATA KSA —
  anyone can download every airline's signing cert). forge boarding passes for any
  flight, any airport, any passenger name.
- **airport sterile area access**: a forged boarding pass with a valid airline
  signature passes TSA document verification. combined with a forged or stolen
  photo ID, the attacker reaches the sterile area of any US airport. same in EU
  (Schengen security perimeter) and Asian hubs (HKG, SIN, NRT).
- **TSA PreCheck abuse**: the PreCheck indicator (KTN field with airline signature)
  lets a passenger skip enhanced screening. a forged PreCheck indicator bypasses
  advanced imaging and shoe/laptop removal. repeat the attack daily at any US
  airport with a forged signed BCBP.
- **Secure Flight evasion**: the BCBP signature is tied to Secure Flight vetting
  in the DCS. forged BCBPs with different names allow someone on a no-fly list to
  travel under different identities — the signature lends authenticity to
  identities that were never vetted.
- **fraud**: sell forged boarding passes on the secondary market — not for flight
  (airline DCS still knows who's booked) but for lounge access, sterile-area dining,
  or duty-free shopping access at connecting hubs without a real ticket.
- **operational disruption**: flood boarding gates with forged boarding passes
  at peak travel time at a target airport. gates reject real and forged passes
  alike while staff investigate. the attack has a linear-in-boarding-passes cost
  since signing is cheap once the RSA key is factored.
- **downstream**: forged wallet-pass updates push false gate/delay info to
  passengers of a target flight. "gate changed to C45" sends them to the
  opposite end of the terminal; "flight cancelled" drives them to rebooking desks
  en masse.

## Code

`bcbp_sign.py` — `parse_bcbp()` (parse PDF417 payload per Resolution 792),
`sign_bcbp()` (RSA-SHA256 signature over M1 mandatory + conditional data),
`verify_bcbp()` (verify signature against IATA KSA trust store), `issue_precheck_bcbp()`
(generate signed BCBP with TSA PreCheck KTN indicator). IATA Key Signing Authority
trust model and airport scanner deployment context in comments.
