# dvb-ci-pay-tv — RSA in pay-TV conditional access (DVB-CI+ CAMs)

**Standard:** DVB CI Plus v1.4 (CI+ Forum); DVB-CI (EN 50221); CableLabs OCAP (US)
**Industry:** Pay television — Sky, Canal+, BeIN, Astro, Foxtel, Nagravision ecosystem
**Algorithm:** RSA-1024 (DVB-CI legacy), RSA-2048 (CI Plus v1.3+ device certs)

## What it does

Every set-top box or integrated digital TV that supports a removable Conditional
Access Module (CAM) implements DVB-CI Plus. The CAM — a PCMCIA card with the
operator's CAS (Nagravision, Conax/Kudelski, Viaccess/Verimatrix, Irdeto, Videoguard)
smart card slot — decrypts encrypted broadcast content and passes it back over the
CI+ interface to the host TV/STB.

CI+ adds cryptographic authentication on top of plain DVB-CI to prevent:
1. CAM sharing (one subscription feeding many TVs)
2. Copying high-value content from the CI+ interface
3. Unauthorized middleman devices sitting between CAM and host

The CI+ AKE (Authentication and Key Exchange) uses:
- Device certificates (RSA-2048) issued by the CI+ Root CA (operated by the CI Plus
  Forum / Trusted Labs in France) to every CAM manufacturer (Neotion, SMiT, Smardtv,
  WISI, Deltacam) and every host TV/STB manufacturer (Samsung, LG, Sony, Philips,
  Panasonic, basically every TV brand sold in Europe/Asia)
- RSA-2048 signing for the AuthKey derivation
- AES-128 for subsequent Content Control (CC) data encryption on the CI+ interface

The CI+ Root CA RSA key signs every manufacturer CA. Every CAM and every CI+
host TV/STB carries an X.509 cert chaining to that root. The cert + the private
key are inside each CAM/host at manufacture.

Deployment: every pay-TV subscriber in Europe with a CAM has one of these —
Sky Germany (Nagravision via CAM), Canal+, TNT Sat, Tivùsat, Freeview Play, Movistar+
Spain, SES HD+ Germany, UK Freesat. Also Asian operators (Astro Malaysia, MyRepublic
Singapore, Turksat). Tens of millions of CAMs, hundreds of millions of CI+-compliant
TVs and STBs.

## Why it's stuck

- CI Plus 1.4 (2016) is the current spec; no 2.0 with PQC is in draft. CI Plus
  Forum is a closed industry body (major broadcasters + CAM vendors + TV OEMs).
- Device certificates are embedded at manufacture in TV/STB silicon or a secure
  element on the CAM. TVs have 10-15 year field life; a TV sold in 2022 will still
  be in someone's living room in 2035, running CI+ with factory-embedded RSA-2048.
- CAMs are PCMCIA cards users can buy independently. A CAM bought in 2018 contains
  an RSA-2048 keypair and cert that are cryptographically fixed; replacing the
  algorithm means replacing the CAM.
- Broadcasting chains are long-term contracts (Premier League, Bundesliga, UEFA
  multi-year TV deals). The delivery chain — encoder → multiplexer → uplink → DVB-S2
  → set-top → CI+ CAM → decryption — is end-to-end tested and expensive to change.

## impact

CI+ is what monetizes premium live sports, pay-TV channels, and premium on-demand
in Europe and much of Asia. break the RSA chain and the whole business model of
pay-TV encryption collapses for anything still using DVB-CI+.

- factor the CI Plus Root CA RSA-2048 key. CI+ Forum distributes the root public key
  in its certification documents, which are freely available to members and leaked
  frequently. Once factored, issue device certificates under forged manufacturer CAs.
- **universal CI+ CAM emulator**: software CAMs that authenticate to any CI+ host
  TV as a legitimate CAM, with valid device certificate. Extract CW (Control Words)
  from encrypted broadcast streams in software, redistribute freely. Card-sharing
  networks (already huge in Europe) go from card-emulator-over-obfuscated-protocol
  to fully-authenticated CI+ compliance.
- **host device impersonation**: forge a CI+ host device cert, present as any TV
  brand/model. CAM happily hands decrypted content + Content Control metadata
  (copy protection flags) to an attacker device. Clean PVR-quality capture of
  all decrypted content, including 4K HDR premium sports.
- **Content Control bypass**: the CC subsystem controls output protection (HDCP
  enforcement, recording restrictions, time-shift windows). Forged host cert with
  chosen cert capabilities = attacker decides what protection is enforced. "No copy"
  content becomes "copy freely."
- **revocation failure**: the CI+ Revocation List (stored in host devices and CAMs,
  updated via EMM) is signed by the CI+ Root. Factor the root → forge revocation
  lists to unrevoke previously revoked device certs (reactivating compromised CAMs),
  or revoke competing operators' device certs (DOS on their subscribers).
- **downstream to ATSC 3.0**: the US ATSC 3.0 broadcast standard and its
  BFO (Broadcaster's Certificate) rely on an analogous RSA-2048 PKI. Same attack
  surface will apply as ATSC 3.0 rolls out over-the-air paid content in the US.
- **sports piracy scale**: already a multi-billion-euro problem. CI+ was the last
  widely-deployed technical barrier against pure software piracy of live sports.
  A working factoring attack reduces it to zero.

## Code

`dvb_ci_ake.c` — `ci_plus_verify_device_cert()` (CI+ AKE: verify peer device
certificate against CI+ Root CA), `ci_plus_ake_derive_akey()` (RSA-2048 signed
AuthKey derivation between host and CAM), `ci_plus_decrypt_cw()` (recover
Control Words from CAM-delivered encrypted CW stream), `ci_plus_revoke_check()`
(check device cert against signed Revocation List). CI Plus Forum trust anchor
and CAM ecosystem context in comments.
