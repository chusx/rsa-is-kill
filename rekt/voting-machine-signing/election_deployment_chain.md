# Voting-machine firmware + ballot signing — consumer paths for
# `voting_rsa_firmware.c`

The RSA verify primitive in `voting_rsa_firmware.c` is invoked at
multiple points across the US election-technology supply chain, and
in parallel stacks in India (EVM-VVPAT), Brazil (TSE UE), the
Netherlands (legacy Nedap, retired but archival), Estonia (i-Voting
TLS + ballot signing), and Switzerland (Swiss Post online voting).
In the US, EAC-certified vendors are: Dominion Voting Systems,
Election Systems & Software (ES&S), Hart InterCivic, Clear Ballot,
Smartmatic. All five rely on RSA at multiple layers.

## Supply-chain touchpoints

### 1. Firmware image signing (vendor side)

Every release of the vendor's ballot-marking device (BMD), optical
scanner, central-count unit, or Election Management System (EMS)
server is RSA-signed by the vendor's engineering-release HSM. The
EAC Voluntary Voting System Guidelines (VVSG 2.0 § 14.4.x) require:

- Vendor-controlled RSA-2048+ signing key, HSM-resident.
- Signature verified by the target device's bootloader before
  executing the firmware.
- Signed hash published to the state's election-IT office at
  least N days before the election (chain-of-custody attestation).

### 2. State EAC certification trust bundle

The EAC Testing & Certification program maintains a list of hashes
for approved firmware builds. County election officials verify the
`SHA-256(firmware.bin)` against the EAC-published list. Vendor
signature validation inside the device chains to vendor root; EAC
hash list chains to a federal-level RSA signature on the master
index file.

### 3. Ballot definition signing

County-produced ballot definition files (`.bdf`, `.edf`, vendor-
specific) are RSA-signed by the EMS when produced, transported to
precinct devices on encrypted USB (or in some legacy jurisdictions,
Zip disk / compact flash), and verified by the device firmware
before unlocking "election mode".

### 4. Cast-vote record (CVR) + results tapes

End-of-day results tapes in the newer generation (Dominion ImageCast
X, ES&S ExpressVote) are signed by the device's per-unit RSA key;
central-count consolidation on the EMS verifies every precinct's
signature before aggregating.

### 5. Post-election audit / RLA (Risk-Limiting Audit)

Colorado's RLA (statutory since 2017), Georgia's post-2020 RLAs,
Pennsylvania + Michigan 2022+ audits walk the CVR files with their
attached RSA signatures to establish chain of custody from scanner
→ audit station.

## Process chain-of-custody ceremony (Colorado SoS playbook)

    # Pre-election: firmware-sync day (L&A testing)
    - County clerk fetches EAC-published SHA256 list + RSA-signed
      manifest; sos-cli verify-manifest manifest.sig manifest.json
    - For each machine: connect via admin-key USB, upload
      vendor-signed firmware bundle, `ics-verify-firmware --cert
      dominion-fw-ca.pem bundle.img` runs on-device, refuses if
      signature fails
    - Hash of installed firmware reported upstream to SoS inventory

    # Election day: ballot definition load
    - EMS signs ballot definition, encrypted USB handed by sworn
      warehouse officer to precinct judge (bipartisan pair)
    - Precinct device verifies RSA signature on boot; if failed,
      unit is quarantined and backup BMD is used

    # Close of polls
    - Device prints results tape + writes signed CVR bundle to USB
    - Precinct judges sign physical tape; CVR bundle transported
      to central count; EMS verifies per-unit signature before
      aggregating

## Breakage

A factoring attack against:

- **A vendor firmware signing key** (Dominion, ES&S, Hart): attacker
  mints a firmware image every certified device in that vendor's
  fleet accepts. Every machine of that vendor deployed in any US
  state becomes a bootkit target. Mitigations are hardware-write-
  protected bootloaders on newer models but not all legacy devices.
- **The EAC manifest signing key**: attacker publishes a
  manifest-claimed-EAC-approved firmware that isn't actually EAC
  certified; county clerks verifying hashes against the signed
  manifest are defeated because the manifest itself is forgeable.
- **A county EMS signing key**: attacker forges ballot definition
  files or CVR exports for a specific jurisdiction. Scope:
  one county's returns.
- **A per-device RSA key**: attacker substitutes CVRs from a single
  scanner or BMD, changing the visible count on that device's
  results tape while leaving paper ballots unaltered. Detectable
  only via RLA on paper; RLAs are rare and partial.

Unlike TLS, a voting-system RSA compromise has no revocation path
fast enough to matter — election-day operations are single-shot
ceremonies, and firmware-rotation cycles are months long. Public
trust consequence is independently significant from technical
impact.
