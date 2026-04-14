# iso15118-ev-charging — RSA in EV charging authentication

**Standard:** ISO 15118-2:2014 (Vehicle-to-Grid communication), IEC 61851  
**Industry:** Automotive, EV charging infrastructure, energy  
**Algorithm:** RSA-2048 (V2G PKI certificates), ECDSA P-256 (allowed alternative)  
**PQC migration plan:** None — ISO 15118-20 (2022) does not mandate PQC; V2G PKI has no PQC roadmap

## What it does

ISO 15118 is the communication standard between electric vehicles and charging stations.
The "Plug and Charge" (PnC) feature in ISO 15118-2 lets an EV automatically authenticate
and pay for charging without any app or card — the car just presents its contract certificate
during the TLS handshake and the session is authorized.

The V2G PKI certificate hierarchy (ISO 15118-2 Annex D):

```
V2G Root CA (RSA-2048, 40-year validity)
  SubCA1 (RSA-2048, 12 years)
    SubCA2 (RSA-2048, 3 years)
      SECC Leaf Cert (charging station TLS cert, 2 years)
      OEM Provisioning Cert (burned into car at manufacture, 6 years)
        Contract Cert (EV payment credential, 2 years, updatable via OTA)
```

The SECC (Supply Equipment Communication Controller) is the charging station's
embedded computer. The EVCC (Electric Vehicle Communication Controller) is in the car.
TLS 1.2 mutual authentication using these RSA-2048 certificates is mandatory.

EU law (Regulation 2023/1804) mandates ISO 15118 support for all new public fast chargers.

## Why it's stuck

- ISO 15118-20 (2022) updated the protocol but did not add a PQC cipher suite or
  new PKI algorithm requirements. The TLS 1.3 support in -20 helps session security
  but doesn't change the certificate algorithm
- The V2G Root CA is operated by Hubject (the largest V2G PKI operator globally).
  Transitioning the root means re-issuing the entire certificate chain for every
  charging station and every car in the ecosystem simultaneously
- Cars have 10-15 year lifespans. An EV manufactured today with an OEM provisioning
  certificate burned into its secure element will be driving in 2039
- Charging station hardware (SECC) has 7-10 year replacement cycles
- No PQC algorithm is defined in the ISO 15118 or IEC 61851 standards body work items

## impact

EV charging "Plug and Charge" is basically a payment and identity system embedded
in the car. the V2G Root CA's RSA-2048 key signs everything. one key, entire charging
ecosystem.

- factor the V2G Root CA RSA key (it's in every certificate distributed with every
  charging station), forge a fake SECC certificate for any charging station. every EV
  that connects will present its contract certificate (payment credential) to your fake
  charger. harvest EMAIDs and contract certs from every car that plugs in
- forge a fake contract certificate for any EMAID. charge on someone else's account
  at any ISO 15118 Plug and Charge station, anywhere in the ecosystem that trusts
  the same V2G Root CA
- the OEM provisioning cert is burned into the car's secure element at manufacture.
  factor the OEM CA RSA key and forge provisioning certificates for every car that
  manufacturer ever made
- cars have 10-15 year lifespans. EV fleet being built today will be driving in 2039
  with RSA-2048 certs that cannot be updated without the OEM pushing an OTA to every
  car's secure element, which is not a thing that routinely happens

## Code

`iso15118_tls_auth.py` — `generate_secc_certificate()` (RSA-2048 SECC TLS cert per
ISO 15118-2 Annex D), `generate_contract_certificate()` (EV payment credential), and
`secc_tls_server()` (mandatory mutual TLS with ISO 15118-2 cipher suite).
