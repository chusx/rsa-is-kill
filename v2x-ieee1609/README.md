# v2x-ieee1609 — ECDSA in connected vehicles

**Standard:** IEEE 1609.2-2022 / ETSI TS 103 097 (EU equivalent)  
**Industry:** Automotive V2X (Vehicle-to-Everything) — safety-critical  
**Algorithm:** ECDSA-P256 (secp256r1), ECDSA-P384 (secp384r1)  
**PQC migration plan:** None — no PQC profile in IEEE 1609.2 or ETSI TS 103 097

## What it does

V2X communications (C-V2X, DSRC/802.11p) allow vehicles to broadcast Basic
Safety Messages (BSMs) 10 times per second to surrounding vehicles and
infrastructure. BSMs contain position, speed, and heading — they are used by
automated emergency braking, intersection collision avoidance, and platooning.

Every BSM is signed with ECDSA-P256 using a short-lived pseudonym certificate.
The US Security Credential Management System (SCMS) issues ~300 million
pseudonym certificates per year. The full trust chain:

```
Root CA (P-384) → PCA (P-256) → Pseudonym Cert (P-256) → BSM signature
```

Every level of the chain uses ECC. Shor's algorithm breaks ECDSA exactly as
it breaks RSA.

## Why it's stuck

- DSRC (802.11p) and C-V2X radios have fixed cryptographic hardware
- Pseudonym certificates are issued by the SCMS 7 days in advance; vehicles
  store hundreds of certs in on-board hardware security modules
- IEEE 1609.2 would need a new version with PQC algorithm OIDs
- Both the US SCMS and European C-ITS trust authority would need to be rebuilt
- Vehicles have 15-20 year lifespans; hardware HSMs cannot be field-updated

A CRQC forging BSMs could broadcast false safety-critical messages (phantom
emergency brakes, false intersection signals) to any vehicle in radio range.

## impact

V2X is how connected vehicles communicate safety-critical information to each other and to roadside infrastructure. ECDSA P-256 under Shor's algorithm means an attacker can sign arbitrary V2X messages as any vehicle or RSU.

- forge Basic Safety Messages with false position, speed, and heading. inject phantom vehicles into the cooperative awareness picture of every nearby car. automated emergency braking and intersection collision avoidance systems respond to the fake vehicles
- forge SPAT messages from a roadside unit telling cars a red light is green. or that a green is red, gridlocking intersections
- V2X pseudonym certificates rotate weekly to protect privacy but the underlying ECDSA P-256 is the same. Shor's algorithm doesn't care how often you rotate a broken algorithm
- SCMS (Security Credential Management System) is the V2X PKI. forge the root CA key and issue arbitrary pseudonym certificates for any vehicle
## Code

`ieee1609_dot2_ecdsa.c` — `ieee1609_sign_bsm()` showing ECDSA-P256 signing of
BSM payload and the full SCMS certificate hierarchy comment.
