# voting-machine-signing — RSA in EAC-certified election firmware (ES&S, Dominion, Hart)

**Repository:** ES&S EVS, Dominion Democracy Suite, Hart Verity — proprietary; analyzed at Defcon Voting Village 
**Industry:** Election infrastructure 
**Algorithm:** RSA-2048 (firmware signing, per EAC VVSG 2.0 Section 13) 

## What it does

ES&S, Dominion, and Hart each produce certified voting equipment (optical scanners, DREs,
ballot marking devices, central count systems) that runs EAC-certified firmware. VVSG 2.0
requires digital signature verification for all software — in practice RSA-2048 PKCS#1 v1.5
on a SHA-256 hash. The machine's bootloader checks the signature before booting election
software. If the signature fails, the machine refuses to start.

The manufacturer CA certificate (the trust anchor) is a self-signed RSA-2048 cert unique
to each vendor. It's not in any public PKI. States receive it as part of the certification
package. Critically, it's also embedded in every firmware image header alongside the leaf
signing cert, in DER-encoded form, in plaintext — so anyone who has a firmware image has
the public key they'd need for input for the attack.

Firmware images have been disclosed at:
- Defcon Voting Village (hardware and firmware analyses since 2018)
- Public records requests (several states disclose firmware as public records)
- Academic security research (Appel, Stark, Blaze, etc.)

## Why it's stuck

- EAC VVSG 2.0 certifies systems to specific algorithm requirements. A manufacturer
 changing from RSA-2048 to ML-DSA needs re-certification — full EAC test campaign,
 which takes 1-3 years and hundreds of thousands of dollars per platform.
- Voting equipment procurement cycles are long. A state that bought DS200 units in
 2019 isn't replacing them until 2026-2030. The firmware signing algorithm is baked
 into the hardware bootloader, which requires a hardware revision to change.
- Election officials have a high bar for "change anything about certified systems."
 The political and legal liability of deploying uncertified firmware is enormous.
 Even a clearly beneficial security update gets stuck in certification hell.
- EAC hasn't published any guidance on non-RSA cryptography for voting systems.
 NIST SP 1800-28 (the companion to VVSG) predates the NIST non-RSA standards.

## impact

ok so this one is pretty special because the threat model here isn't just "system
compromised" it's "election integrity is gone and you can prove it after the fact
which is somehow worse"

- every firmware image embeds the manufacturer CA cert in plaintext. get one firmware
 image (Defcon Voting Village has analyzed several publicly). factor the RSA-2048 CA key.
 now you can sign firmware that passes the bootloader check on every machine from
 that manufacturer, in every state that uses that manufacturer's equipment.
- ES&S DS200 is in ~44 states. Dominion is in ~28. forge firmware for either vendor,
 deploy it — somehow — to machines before an election. the L&A testing process checks
 that firmware version strings match. your firmware reports the correct version string
 and passes L&A because the signature also matches. the L&A test passes.
- what does your firmware do? that's the fun part. it can count votes correctly in the
 L&A test (which uses a known ballot set) and do something different on election day
 (which uses a different ballot set). this is not a new attack; it's been described
 in academic literature since 2006. the RSA signature was supposed to be the fix.
- post-election audits: risk-limiting audits check paper ballot counts against machine
 counts. if your firmware modification also alters the paper ballot pathway (it depends
 on the machine design), the RLA won't catch it. if it doesn't, the RLA will.
 so the attack has to be careful. but the prerequisites used to include "find zero-days
 in the machine OS" and now they're just "factor RSA-2048."
- international: many democracies use equipment from these same manufacturers or their
 subsidiaries. SCYTL, Smartmatic, and others use similar RSA-based firmware auth.

## Code

`voting_rsa_firmware.c` — `vs_verify_firmware()` (RSA-2048 PKCS#1 v1.5 boot verification,
X.509 chain to manufacturer CA, SHA-256 body integrity check), `vs_sign_firmware()`
(manufacturer HSM signing operation). EAC VVSG 2.0 / state certification context in comments.
Defcon Voting Village research referenced for firmware image availability.
