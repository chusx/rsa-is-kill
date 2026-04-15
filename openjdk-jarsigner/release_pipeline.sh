#!/bin/bash
# release_pipeline.sh
#
# jarsigner-driven JAR release signing pipeline. Invokes the
# RSA-default signing path in `JarSigner_rsa_default.java` through
# the JDK `jarsigner` tool. This is the workflow every major Java
# ecosystem vendor runs on their build boxes.
#
# Deployed at:
#   - Oracle WebLogic / E-Business Suite / Oracle Cloud JARs
#   - Red Hat JBoss EAP / WildFly release artifacts
#   - Apache Maven Central Sonatype OSS repository (required for
#     every release coordinate; `maven-gpg-plugin` + jarsigner both
#     on the chain)
#   - Eclipse Foundation p2 repositories (RCP/IDE plug-ins signed
#     under the Eclipse release cert)
#   - Minecraft Java Edition + Forge mod loader
#   - Android SDK tools zips (before APK signing takes over)
#   - JetBrains (IntelliJ IDEA, PyCharm, CLion) — IDE plugin
#     signatures verified by the JetBrains Marketplace

set -euo pipefail

JAR=${1:?jar path}
ALIAS=${2:?keystore alias (e.g. release-signer-2026)}
KEYSTORE=${3:-"pkcs11"}          # pkcs11 for HSM-backed, .jks for legacy
TSA=${4:-"http://timestamp.digicert.com"}

# ---- 1. Pre-flight ----
test -f "$JAR" || { echo "missing $JAR"; exit 2; }

# ---- 2. Sign ----
#
# Real release hosts use the PKCS#11 provider pointing at a Thales
# Luna / Utimaco / AWS CloudHSM slot so the RSA-3072 / RSA-4096
# private key never leaves the FIPS module. The sigalg default has
# been RSA+SHA256 since JDK 7u111; modern releases use RSA+SHA-384 or
# RSA-PSS.
if [[ "$KEYSTORE" == "pkcs11" ]]; then
    jarsigner \
        -keystore NONE \
        -storetype PKCS11 \
        -providerClass sun.security.pkcs11.SunPKCS11 \
        -providerArg /etc/pkcs11/cloudhsm.cfg \
        -sigalg SHA384withRSA \
        -digestalg SHA-384 \
        -tsa "$TSA" \
        -tsapolicyid 2.16.840.1.113733.1.7.23.3 \
        -tsadigestalg SHA-256 \
        -signedjar "${JAR%.jar}-signed.jar" \
        "$JAR" "$ALIAS"
else
    jarsigner \
        -keystore "$KEYSTORE" \
        -storepass:env KEYSTORE_PASS \
        -keypass:env KEY_PASS \
        -sigalg SHA384withRSA \
        -digestalg SHA-384 \
        -tsa "$TSA" \
        -signedjar "${JAR%.jar}-signed.jar" \
        "$JAR" "$ALIAS"
fi

# ---- 3. Verify ----
#
# -strict forces full chain validation + TSA countersig check.
# Exit code non-zero on ANY warning (expired cert, missing TSA
# response, out-of-validity signing).
jarsigner -verify -strict -verbose -certs "${JAR%.jar}-signed.jar"

# ---- 4. Publish ----
#
# Maven Central requires detached .asc PGP signatures on every
# artifact IN ADDITION to jarsigner embedded signatures — see
# `gnupg/release_signing_workflow.sh` for that second layer.
aws s3 cp "${JAR%.jar}-signed.jar" \
    "s3://release-artifacts.corp.example.com/$(date +%Y-%m-%d)/"

# ---- 5. Capability announce ----
#
# Signed JARs in the JVM classloader:
#   - Unlock the "security-sensitive" APIs in applet / Web Start
#     land (historical, but still live in some enterprise back-
#     office apps).
#   - Unlock Java Plug-in / jlink --module-path trust for internal-
#     only subsystems.
#   - Needed for com.sun.* + sun.misc.* reflection in older JARs.
#   - Grant permissions in a SecurityManager-enabled JVM via
#     policy-file `signedBy "release-signer"` grants.
#
# A factoring attack on the release-signer's RSA key lets an
# attacker mint maliciously modified JARs that every legitimate
# classloader admits into those trust tiers:
#   - Replace a signed "oracle-jdbc.jar" in an EBS deployment and
#     the JVM's SecurityManager grants it DB network access +
#     signed-code privileges.
#   - Substitute a Forge mod or Minecraft launcher component on
#     the Mojang distribution CDN.
#   - Push a malicious IntelliJ plugin update whose JetBrains
#     Marketplace signature re-verifies.
# Because jarsigner timestamps each signature against an RFC 3161
# TSA, archival JARs remain verifiable long after cert expiry —
# which also means a factored key retroactively ratifies attacker
# re-signings that appear historically authentic.
