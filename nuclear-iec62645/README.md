# nuclear-iec62645 — RSA in nuclear I&C firmware signing (RPS, ESFAS, TRISIS target class)

**Repository:** IEC 62645 / NRC RG 5.71 implementations — Siemens SPPA-T3000, Emerson Ovation, Schneider Tricon  
**Industry:** Nuclear power, petrochemical safety systems  
**Algorithm:** RSA-2048 (I&C firmware signing, vendor CA cert embedded in firmware images)  
**PQC migration plan:** None — no PQC in IEC 62645:2014, no revision in progress; NRC RG 5.71 doesn't mention post-quantum; no I&C vendor has published a PQC firmware signing roadmap

## What it does

Nuclear instrumentation and control systems — reactor protection (SCRAM logic), engineered
safety features (emergency core cooling, containment isolation), neutron flux monitoring —
run on specialized platforms from Siemens (SPPA-T3000), Emerson (Ovation), and Schneider
(Tricon/Triconex). IEC 62645 and NRC RG 5.71 require "integrity verification" for safety
software to prevent unauthorized modification.

In practice this means every firmware update carries an RSA-2048 signature from the vendor's
private CA (stored in an HSM at the vendor facility). The I&C controller's bootloader verifies
the signature before applying any update. The vendor CA certificate is burned into the
controller's tamper-resistant flash at manufacture. The leaf signing cert is embedded in
the firmware image header, DER-encoded, plaintext, available to anyone who has a copy of
the firmware.

Applies to:
- Siemens SPPA-T3000 — installed at ~170 nuclear units worldwide (German, French, South Korean)
- Emerson Ovation — US and European reactor control
- Schneider Tricon v11 — safety instrumented systems at petrochemical and nuclear plants
- Mitsubishi MELTAC — Japanese BWR/PWR protection systems
- Rolls Royce Hi-Q (formerly PLEX) — UK nuclear instrumentation

The TRISIS/TRITON attack (2017) targeted a Saudi Aramco facility running Triconex SIS.
The attackers found Triconex firmware zero-days. The current Tricon v11 firmware signing
uses RSA-2048 — the improvement Schneider made after TRISIS.

## Why it's stuck

- Nuclear I&C software is qualified under 10 CFR 50 Appendix B and IEEE 603. Changing the
  cryptographic algorithm in the bootloader requires a full software qualification cycle:
  design, V&V, testing, independent assessment, NRC review. This process takes 5-10 years
  and costs tens of millions of dollars per platform.
- The signing CA certificate is burned into hardware at manufacture. Updating it requires
  physical access to every controller in every plant, which means a refueling outage
  (scheduled every 18-24 months). Coordinating across all plants worldwide is a decade-scale
  project even once a replacement algorithm exists.
- IEC 62645 is published by IEC TC45/SC45A. The current edition is 2014. There is no
  published revision schedule and no PQC work item in the TC45 work program.
- NRC RG 5.71 references "approved cryptographic algorithms" pointing to FIPS 140-2 era
  standards. The update cycle for NRC regulatory guides is measured in years.

## impact

this is the safety system at nuclear power plants. the RSA signature is the only technical
control preventing "load arbitrary firmware onto the reactor protection system."

- derive the vendor signing key from any firmware image (the cert is in the header, public,
  DER-encoded). sign arbitrary replacement firmware. send it to any reactor running that
  I&C platform. the bootloader accepts it, installs it, reboots into your code.
  the SCRAM logic now does what you want
- TRISIS/TRITON had to find zero-days in Triconex firmware to do this. with RSA broken,
  the zero-days are unnecessary. the "improvement" Schneider made post-TRISIS was RSA
  signing. that improvement is gone.
- for SPPA-T3000: ~170 nuclear units worldwide. one vendor CA. one RSA-2048 key.
  all 170 units accept firmware signed with that key. a single CRQC factoring operation
  is a pass to every Siemens-controlled reactor on earth.
- not just reactors: same class of systems controls petrochemical safety interlocks,
  LNG plant emergency shutdowns, offshore platform blowout preventers. TRISIS wasn't
  at a reactor. it was at an oil and gas facility. same code signing model.

## Code

`nuclear_rsa_sign.c` — `nic_verify_firmware()` (RSA-2048 PKCS#1 v1.5 signature verify
over SHA-256 of firmware body, X.509 cert chain to vendor CA), `nic_sign_firmware()`
(vendor HSM signing operation), and SPPA-T3000/Ovation/Tricon deployment context.
IEC 62645 / NRC RG 5.71 regulatory context in comments.
