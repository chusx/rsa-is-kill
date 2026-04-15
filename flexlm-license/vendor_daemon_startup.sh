#!/bin/bash
# vendor_daemon_startup.sh
#
# FlexLM / Flexera Publisher vendor-daemon bring-up — the glue around
# the RSA license-signature verifier in `flexlm_rsa.c`.
#
# This is what runs on license servers for the world's highest-price
# engineering software:
#   - Cadence Virtuoso, Spectre, Palladium (EDA, ~$1M/seat/year)
#   - Synopsys Design Compiler, VCS, ZeBu
#   - Siemens EDA Calibre, Questa
#   - Ansys Fluent, HFSS, Mechanical
#   - Dassault CATIA, ABAQUS, SIMULIA
#   - MATLAB / Simulink fleet licensing
#   - PTC Creo, Windchill
#   - Autodesk network licensing (pre-subscription holdouts)
#
# The vendor daemon checks out RSA-signed feature records to running
# engineering tools over TCP.  Compromise of the signing key lets
# anyone mint valid license files for any product in the ecosystem.

set -euo pipefail

VENDOR=${1:?vendor name required (e.g. cdslmd, snpslmd, mgcld, ansyslmd)}
LICPATH=/opt/flexlm/licenses/${VENDOR}.lic
LOGFILE=/var/log/flexlm/${VENDOR}.log
LMGRD=/opt/flexlm/bin/lmgrd

# ---- Pre-flight: licence file sanity ----
#
# lmgrd will refuse to start if the RSA signature on the SERVER/VENDOR
# lines (the 20-hex-char SIGN= token after each INCREMENT) does not
# check out under the vendor's embedded public key.  On Cadence/Synopsys/
# Ansys builds the public key is compiled into the vendor daemon
# binary (cdslmd, snpslmd, ansyslmd).

if ! "$LMGRD" -lmdiag -c "$LICPATH" >/dev/null 2>&1; then
    echo "licence diag failed (signature or platform mismatch)"
    exit 2
fi

# ---- Start lmgrd + vendor daemon.  lmgrd spawns the vendor daemon
#      as a child; the vendor daemon re-verifies the signatures on
#      INCREMENT lines every time a client checks out a feature.  ----

exec "$LMGRD" \
    -c "$LICPATH" \
    -l  "$LOGFILE" \
    -local \
    -reuseaddr &

# ---- Monitoring: watch for signature-mismatch errors in the log ----
#
# Typical error patterns:
#   2026-04-15 08:12:33 (cdslmd) Invalid license file syntax
#   2026-04-15 08:12:33 (cdslmd) Invalid (inconsistent) license key.
#   The license-key and data for the feature do not match.
#   This usually happens when a license file has been altered.
#
# These always indicate either a hand-edited feature line (attempted
# to bump --count or --duration) or a forged file minted with the wrong
# RSA private key.
tail -F "$LOGFILE" | grep --line-buffered -iE \
    "invalid license|signature|tampered|inconsistent" \
    | logger -t flexlm-tamper &

# ---- Breakage under an RSA factoring attack ----
#
# Flexera uses per-vendor RSA key pairs (historically 768-bit in very
# old builds, upgraded to 1024 then 2048 through the 2010s). Ecosystem
# vendors ship the public key embedded in their daemon binaries. An
# attacker who factors a vendor key can:
#   - Mint arbitrary INCREMENT lines ("INCREMENT VCS-MX-I Synopsys
#     9999.9999 31-dec-2099 9999 SIGN=...") that any lmgrd + vendor
#     daemon in the field accepts as authentic.
#   - Bypass feature-expiry, user-count, hostid-binding — basically
#     reduce $1M/year EDA licensing to a matter of correctly
#     computing a signature. This is already the economic incentive
#     behind the whole "EDA license cracker" underground; a real
#     factoring primitive industrializes what's currently bespoke
#     reverse-engineering per release.
