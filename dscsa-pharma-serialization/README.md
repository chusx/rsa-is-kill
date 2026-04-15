# DSCSA + EU FMD — pharmaceutical serialization & signed traceability

The US Drug Supply Chain Security Act (DSCSA, Title II of the
Drug Quality and Security Act, fully enforceable November 2024)
and the EU Falsified Medicines Directive (FMD, Delegated
Regulation 2016/161, live since February 2019) require every
prescription drug package to carry a serialized 2D DataMatrix code
and for every handoff in the supply chain to generate a signed
EPCIS (Electronic Product Code Information Services) event
exchanged between trading partners.

## RSA touchpoints

1. **AS2 (Applicability Statement 2, RFC 4130)** — the dominant
   B2B transport for EPCIS messages between manufacturers,
   wholesale distributors (McKesson, Cardinal Health, AmerisourceBergen),
   3PLs, and dispensers (CVS, Walgreens, Walmart). AS2 envelopes
   are S/MIME-signed + encrypted under RSA-2048/4096 partner
   certificates exchanged ahead of go-live.

2. **EPCIS document signing** — GS1 EPCIS 2.0 supports XAdES-based
   XML signatures over the whole event document; many trading
   partners add an XMLDSig-RSA signature per-event for evidentiary
   integrity in recall/traceability investigations.

3. **EU NMVS / EMVS hub** — the European Medicines Verification
   System. Every dispenser decommission call (a pharmacy scanning
   a pack at dispensing time) runs over TLS-client-cert mutual auth
   using RSA-2048 certs issued by the national Medicines
   Verification Organisation (NMVO). Every pack verification
   response is RSA-signed.

4. **FDA FURLS / ESG (Electronic Submissions Gateway)** — Drug
   Listing, Establishment Registration, and DSCSA-required
   notifications submitted to FDA via AS2 with RSA S/MIME.

5. **Serialization vendor platforms** — Tracelink, SAP ATTP / SAP
   Advanced Track and Trace for Pharmaceuticals, Systech UniSecure,
   Adents Seriation Manager, Rfxcel, Optel Group — all of them sit
   between manufacturers' MES (Rockwell, Siemens) and trading-
   partner ERPs (SAP, Oracle) and sign outbound EPCIS messages
   with an RSA key held in the cloud-platform HSM.

## Operational footprint

- Every prescription drug pack sold in the US, EU-27, Turkey,
  Saudi Arabia, UAE, Russia, China (GS1 DataMatrix variant),
  Brazil, India — pushing 200+ billion unit-level scans per year.
- Dispenser decommission is real-time: every pharmacy scan at
  checkout hits the national NMVS hub via authenticated TLS, gets
  back an RSA-signed verify response.
- Recall responses: when a batch is recalled, the full genealogy
  of signed EPCIS events is the evidence chain that regulators
  (FDA, EMA) use to identify downstream dispensers. Archival life:
  6 years (DSCSA) / 10 years (EU FMD).

## Breakage

A factoring attack against:

- **A national NMVO CA** (UK SecurMed, France CIP-Pharma, Italy
  NSIS, Germany securPharm): attacker mints forged dispenser and
  wholesaler certs, floods the NMVS with decommission-OK responses
  for counterfeit packs. Legitimate supply chain can no longer
  distinguish genuine from forged product — counterfeit medicines
  enter the white-market distribution network under cryptographically
  verified provenance.
- **A manufacturer's AS2 RSA key** (Pfizer, Merck, Novartis, Roche,
  GSK): attacker injects forged EPCIS events into trading-partner
  ERPs, misrepresenting chain-of-custody. For controlled substances
  (opioids, Schedule II-V) this has DEA/EMA investigative-evidence
  consequences.
- **A serialization-platform vendor root** (Tracelink, SAP ATTP):
  cross-manufacturer compromise; forged events for any pharma using
  that vendor. Tracelink alone handles >60% of US Rx traceability
  data flow.

Archival retention + inability to retroactively re-sign historical
EPCIS events means a factoring break is permanent evidentiary
ambiguity across years of pharmaceutical chain-of-custody data.
