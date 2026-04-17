# cbrs-sas-spectrum — RSA in FCC 3.5 GHz CBRS spectrum management

**Standard:** WInnForum WINNF-TS-0065 (SAS-CBSD interface), WINNF-TS-0022 (PKI)
**Industry:** Private LTE/5G, WISP, enterprise wireless — 3.5 GHz band (3550-3700 MHz)
**Algorithm:** RSA-2048 (all CBSD device certs, SAS server certs, Domain Proxy certs)

## What it does

CBRS (Citizens Broadband Radio Service) is the FCC's 3.5 GHz band in the US, shared
between incumbent Navy radar, Priority Access Licensees (auction winners — Verizon,
T-Mobile, Dish, cable MSOs), and General Authorized Access users (anybody with a
registered CBSD). Access is coordinated dynamically by a Spectrum Access System (SAS).

Every CBSD (Citizens Broadband Radio Service Device — base stations, small cells, CPE)
must authenticate to an FCC-certified SAS before transmitting. Authentication is mTLS
with RSA-2048 certificates issued under the WInnForum CBRS PKI:

- **Root CA**: WInnForum CBRS Root CA (RSA-2048, 20-year validity)
- **SAS CA**: issues certificates to FCC-certified SAS operators (Federated Wireless,
  Google, CommScope/CTIA, Key Bridge, Sony, RED Technologies)
- **CBSD CA**: issues certificates to OEMs (Nokia, Ericsson, Samsung, Airspan,
  Baicells, Cambium, Ruckus, JMA Wireless) who provision per-device certs
- **Domain Proxy CA**: for aggregators that front multiple CBSDs to SAS

The SAS-CBSD protocol (WINNF-TS-0016) runs over HTTPS with mutual TLS. Every
`cbsdRegistrationRequest`, `cbsdSpectrumInquiryRequest`, `cbsdGrantRequest`, and
`cbsdHeartbeatRequest` is authenticated via RSA-2048 TLS client cert.

Deployed in: 250,000+ CBSDs registered with SAS (early 2024 numbers). Used by Verizon
5G Home, Dish 5G, cable MSO (Charter) mobile networks, private enterprise 5G campus
networks (FedEx, Walmart, BP, major hospitals, airports, stadiums).

## Why it's stuck

- WInnForum WINNF-TS-0022 v2.0 hardcodes RSA-2048 as the required key type. No
  working group is drafting an ECDSA/ML-DSA transition.
- FCC Part 96 (2015, updated 2020) references WInnForum specs for SAS authentication.
  Algorithm change triggers FCC rulemaking.
- CBSD devices have certificates burned at manufacture into TPM or secure element.
  Re-certifying existing devices requires OEM firmware updates rolled out to
  every deployed CBSD — logistics comparable to a wireless operator's device fleet.
- Each SAS is FCC-certified (CPE Certification) on a specific crypto stack. A new
  algorithm requires each of the 6+ SASes to re-certify, a multi-year process.

## impact

CBRS is how private LTE/5G operates in the US 3.5 GHz band. forge the SAS auth
and you can transmit on someone else's spectrum, interfere with radar (which is
why incumbents opposed the band going shared in the first place), or DOS
legitimate operators.

- factor the WInnForum CBRS Root CA key. now you can issue SAS, CBSD, and Domain
  Proxy certificates at will. register rogue CBSDs anywhere, with any power level,
  on any frequency. no SAS operator can distinguish them from legitimate devices.
- **Navy radar interference**: CBRS band (3550-3650 MHz) overlaps with SPN-43
  shipborne radar and E-2D Hawkeye. the SAS exists specifically to vacate spectrum
  when ESC sensors detect Navy radar. rogue CBSDs that ignore grant revocations
  can interfere with carrier radar used in aircraft landing approaches to CVN-class
  carriers. the FCC/DoD designed CBRS specifically to prevent this; forging the
  PKI removes the enforcement.
- **spectrum DOS against competitors**: as a PAL holder's rival, forge massive
  numbers of GAA CBSD registrations across their deployment region. PAL protection
  area shrinks as SAS accounts for phantom GAA activity; PAL quality of service
  degrades.
- **spectrum hijack**: forge a PAL-holder identity at their licensed locations,
  get priority access grants, transmit on cleared channels while the real
  licensee's CBSDs get downgraded to GAA or blocked entirely.
- **private 5G compromise**: enterprise campus 5G (hospitals, airports, stadiums,
  industrial plants) is CBRS-based. forge the enterprise's CBSD certificates and
  join their private RAN; now inside the 5G slice that's carrying operational
  traffic for the facility. airport ground ops, hospital pagers, stadium ticketing
  and crowd management.
- **regulatory cascade**: CBRS is the template for Europe's 3.8-4.2 GHz shared
  access (CEPT ECC/DEC(22)06), UK's 3.8-4.2 GHz local access, and Japan's
  private 5G bands. the same PKI model will exist in those regimes.

## Code

`cbrs_sas_auth.py` — `cbsd_register()` (CBSD registration request over mTLS with
RSA-2048 client cert), `verify_cbrs_cert_chain()` (verify CBSD cert against WInnForum
PKI), `cbsd_grant_request()` (authenticated spectrum grant request), `issue_cbsd_cert()`
(CBSD CA signs device cert — the forgeable step). WInnForum CBRS PKI trust model and
FCC Part 96 regulatory context in comments.
