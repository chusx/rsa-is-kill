# railway-ertms — RSA in European Train Control System

**Standard:** ERTMS/ETCS — ERA/ERTMS/033281, SUBSET-114  
**Industry:** Railway signalling and train protection (30+ countries, ~100,000 km)  
**Algorithm:** RSA-2048 (OBU X.509 certs, RBC certs, SUBSET-114 data packages)  
**PQC migration plan:** None — no PQC in ETCS specs; ERA has not published PQC guidance

## What it does

ERTMS/ETCS (European Train Control System) is the mandatory train protection
standard for high-speed and mainline rail across Europe. It uses X.509
certificates for authentication between:

- **OBU** (On-Board Unit, the train) — RSA-2048 device certificate
- **RBC** (Radio Block Centre, the signalling computer) — RSA-2048 server cert
- **SUBSET-114** data packages: firmware, balise databases, speed restriction
  updates — signed with RSA-2048 by the national railway authority

The OBU grants movement authorities (MAs) that tell the train where and how
fast it may proceed. The entire MA issuance flow is authenticated by RSA.

## Safety implications

A forged OBU certificate can receive fraudulent MAs from a compromised RBC.
A forged RBC certificate can issue false MAs to legitimate trains.
Either attack could result in unsafe train movements.

Railway control systems are explicitly named in EU NIS2 Directive (Annex I)
as "essential entities" — the highest regulatory security tier. Yet the
underlying ETCS cryptographic specification has not been updated for PQC.

## Why it's stuck

- **Multi-stakeholder**: ERA coordinates 30+ national railway operators,
  each running their own PKI. A PQC migration requires ERA to mandate a
  new ETCS security annex, then each country to implement it.
- **Interoperability**: An OBU certified in Germany must work on the French
  LGV network. Certificate format changes require new interoperability tests.
- **Hardware lifespan**: OBU hardware lasts 20-30 years. The tamper-resistant
  module holding the RSA private key is typically a smart card or HSM element
  that cannot be remotely re-keyed.
- **FRMCS** (5G successor to GSM-R): also uses X.509 with RSA, no PQC in
  3GPP TR 22.889 (FRMCS security architecture).

## Code

`ertms_x509_certificates.c` — `etcs_obu_rbc_tls_auth()` (mutual TLS with RSA-2048
certs), `etcs_verify_data_package()` (SUBSET-114 RSA firmware verify), and
the ERA CA hierarchy with RSA key sizes and certificate validities.
