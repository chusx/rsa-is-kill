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

## why is this hella bad

V2X messages directly control driver assistance systems and automated vehicles. Forging them is a physical safety attack:

- **Broadcast a fake emergency brake BSM** from a phantom vehicle ahead → every car with forward collision warning brakes simultaneously on a highway → multi-vehicle pile-up
- **Forge false traffic signal SPaT messages** → tell vehicles the light is green when it's red → T-bone collisions at intersections
- **Ghost vehicle injection**: insert a fake vehicle into the local awareness map of an autonomous vehicle → cause it to swerve or stop
- Attack range = radio range (~300m for DSRC, ~1km for C-V2X with roadside units)
- Pseudonym certificate rotation (every few minutes) does not help — all pseudonym certs chain to the same ECDSA CA

## Code

`ieee1609_dot2_ecdsa.c` — `ieee1609_sign_bsm()` showing ECDSA-P256 signing of
BSM payload and the full SCMS certificate hierarchy comment.
