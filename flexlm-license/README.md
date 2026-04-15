# flexlm-license — RSA in FlexLM/FlexNet software license signing (Synopsys, MATLAB, Cadence)

**Repository:** Flexera Software FlexNet Publisher (proprietary); vendor daemon binaries 
**Industry:** EDA, scientific computing, CAD/CAM — essentially all commercial engineering software 
**Algorithm:** RSA-1024 (legacy) / RSA-2048 (current) embedded in vendor daemon binaries 

## What it does

FlexLM (now FlexNet Publisher) is the software license management system used by
virtually every commercial EDA, CAD, and scientific computing vendor. The vendor daemon
has the vendor's RSA public key compiled in. License files contain a `SIGN=` field which
is the RSA signature over the feature name, version, expiry date, and seat count. When
an application checks out a license, the vendor daemon verifies the RSA signature.

The vendor RSA public key is in every installed copy of every vendor daemon:
- `synopsys_lmgrd` — Synopsys Design Compiler, VCS, Primetime, Verdi
- `mlm` (MATLAB License Manager) — MathWorks MATLAB, Simulink, all toolboxes
- `cdslmd` — Cadence Virtuoso, Spectre, Innovus
- `mgcld` — Mentor/Siemens EDA Calibre, Xcelium
- `ansyslmd` — Ansys HFSS, Maxwell, Mechanical
- `catiav5` — Dassault CATIA for Airbus/Boeing structural design
- `MSC.Software` — Nastran, Adams (vehicle and aerospace simulation)

The vendor private key is held by the software vendor. The public key is extractable
from the daemon binary with standard tools (`strings`, `objdump`, or just reading the
RSA key structure directly). People have been extracting these keys and attempting to
crack FlexLM for 30 years. The only thing stopping them is that RSA is hard.

## Why it's stuck

- The FlexLM license format and the vendor daemon protocol are proprietary.
 Changing the signature algorithm requires Flexera to update the framework and every
 vendor to recompile and redeploy their daemon.
- Licensees run FlexLM servers in air-gapped environments (chip design fabs, defense
 contractors). A daemon update requires change management, testing, and often downtime.
- The RSA public key is compiled directly into the vendor application binary, not just
 the daemon. Every application binary that performs license pre-check contains the
 vendor RSA public key. Updating the algorithm means recompiling and redistributing
 every application binary to every licensee.
- Flexera's business model is license compliance enforcement, not cybersecurity.
 They have published zero guidance on non-RSA alternatives.

## impact

FlexLM is why expensive EDA software costs money. RSA is the technical enforcement.

- the vendor RSA public key is in every installed daemon binary, worldwide, on every
 chip designer's workstation. it's been there for 30 years. pull it out, run the factoring algorithm
 algorithm, derive the vendor RSA private key. now sign any license file for any
 feature with any expiry date and any seat count.
- Synopsys DC Ultra is ~$1M/seat. Cadence Virtuoso is ~$500K/seat. MATLAB with all
 toolboxes is ~$50K/year. the RSA signature is the entire technical basis for these
 price points. one one factoring operation, and every software vendor's EDA/simulation/CAD
 product is effectively unlicensed.
- for defense/aerospace: Lockheed Martin, Raytheon, Boeing all run MATLAB, Nastran,
 Simulink, CATIA on FlexLM. their license servers are air-gapped. they're not getting
 a daemon update quickly. and the attack doesn't require network access to their
 license server — just the daemon binary (which ships in the commercial software package).
- universities: every university that runs MATLAB has a FlexLM server. academic
 licenses are institutional. an attacker who can forge a MATLAB license file can give
 every student unlimited MATLAB with every toolbox forever. this is not catastrophic
 in the national security sense but MathWorks would find it notable.
- the more interesting attack is Synopsys/Cadence for semiconductor design. TSMC,
 Intel, Samsung, GlobalFoundries all run massive FlexLM farms for chip design tools.
 if you can generate unlimited Synopsys licenses you can run unlimited IC design jobs.
 the EDA tools are also used to understand chip designs — license forgery plus tool
 access is a route to reverse-engineering advanced semiconductor designs.

## Code

`flexlm_rsa.c` — `flexlm_parse_sign_field()` (SIGN= hex field decoder),
`flexlm_verify_license_feature()` (RSA public decrypt + SHA-1 digest verify, modeling
vendor daemon check), `flexlm_forge_license_feature()` (RSA private sign with derived
key). Vendor daemon list and EDA/simulation deployment context in comments.
