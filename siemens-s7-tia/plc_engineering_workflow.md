# Siemens S7 / TIA Portal — where `siemens_s7_rsa.c` is invoked

Siemens SIMATIC S7-1200 / S7-1500 / ET 200SP / S7-1500 Software
Controller PLCs, programmed via TIA Portal (V15+ introduces RSA-
backed "Secure Communication"; V17+ mandates per-CPU certificates
for protected download).  Deployed in essentially every heavy-
industry sector: automotive assembly lines (VW Wolfsburg, Toyota,
Ford, Stellantis), Siemens-built gas turbines, ABB + Siemens
chemical plants, Wienerberger and Lafarge cement lines, ASML and
Zeiss semiconductor fabs, pharmaceuticals (Roche, Pfizer), food &
beverage (Nestlé, InBev), water/wastewater utilities across the
EU-27.

## Touchpoints

### 1. Engineering station ↔ CPU: protected download

TIA Portal establishes a TLS 1.3 tunnel to the CPU on TCP 4840
(OPC UA) and 102 (ISO-on-TCP / RFC 1006).  V17+ "Secure PG/PC and
HMI communication" binds the TLS handshake to the engineer's
Windows-user cert (mintable from the Siemens UMC ID Store, ADCS,
or a plant-local CA). `siemens_s7_rsa.c::verify_project_signature`
runs CPU-side on every `PLC_Program_Download` block to check the
PKCS#7 signature over the compiled STEP 7 / SCL blocks.

### 2. GSDML / device integration

Profinet IO device descriptions (GSDML XML) shipped by device
vendors (SEW Eurodrive, Festo, Beckhoff) carry XMLDSig-RSA
signatures that TIA Portal validates before the IO controller will
cyclic-exchange frames.

### 3. Firmware update for the CPU + IO modules

`Siemens_CPU_Firmware_V2.9.6.upd` is a signed bundle; the CPU's
bootloader verifies an RSA-2048 signature under the Siemens Code
Signing CA before flashing.  Signature covers the entire image
including the FPGA bitstream.

### 4. PLC↔PLC S7 comms

S7-1500 ↔ S7-1500 "Secure Open User Communication" via TLS mutual
auth; each CPU holds a device cert issued by the plant's TIA UMC or
via manual CSR upload.  The ladder-logic FB `TMAIL_C` / `TUSEND`
hits the TLS stack, which in turn hits the RSA verify path.

### 5. HMI / WinCC Unified Engineering

Runtime downloads to WinCC Unified Comfort Panels are PKCS#7-signed
by the engineering seat; the HMI boot loader refuses to launch an
unsigned project after V17.

## Engineering-workflow snippet

    # TIA Portal CLI (Openness API) — automated build agent pipeline
    $project = Get-TiaProject "LinePackLine3.ap17"
    $cpu     = $project.Devices["PLC_1"]

    # Mandatory signed download (V17+ "Write-access protection 2")
    $cred = Get-SigningCredential -Thumbprint $env:PLANT_ENG_CERT
    Invoke-SecureDownload -Cpu $cpu -SigningCert $cred -ProgramBlocks All

## Relevant protection levels (TIA V17+)

    CPU protection level 4  - engineer cert required for any write
    Write-access protection - RSA-signed project required
    HMI connection auth     - HMI holds its own RSA cert
    Secure OUC              - TLS 1.3 mandatory between CPUs

## Breakage

A factoring attack against:

- **Siemens Code Signing CA**: attacker mints firmware updates the
  CPU bootloader accepts.  Global S7-1500 fleet is one well-crafted
  signed `.upd` away from silent reflash.  Precedent: 2023 Unicorn
  Team S7 CPU takeover required physical access; a signed-firmware
  path removes that constraint.
- **Plant UMC / engineering CA**: attacker walks onto the plant
  network, mints an engineering-workstation cert, and pushes a
  malicious STEP 7 project that the CPU happily loads as a signed
  download.  Stuxnet redux, but with legit signatures the CPU
  cryptographically trusts — no infection-of-Step7.exe needed.
- **Per-CPU device cert**: targeted MITM of PLC↔PLC comms on a
  specific asset; useful for spoofing interlock signals between
  cells on a car-body line or dosing signals on a pharma
  fill-finish line.
