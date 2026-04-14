# OpenJDK jarsigner — RSA JAR Code Signing

**Source:** https://github.com/openjdk/jdk  
**File:** `src/jdk.jartool/share/classes/jdk/security/jarsigner/JarSigner.java`  
**License:** GPLv2 with Classpath Exception

## what it does

`jarsigner` signs Java archives (JARs). The signature is stored as `META-INF/*.RSA` (or `.EC`, `.DSA`) inside the ZIP. Every Java runtime verifies this signature when loading signed JARs from a trusted source. This is the code-signing mechanism for:

- Android APKs (v1 "JAR signing" scheme, still required for compatibility with Android ≤ 6)
- OSGi bundles (Eclipse plugins, enterprise middleware)
- Java EE / Jakarta EE deployment archives
- Maven Central artifact integrity

## why it's broken

- `getDefaultSignatureAlgorithm()` delegates to `SignatureUtil.getDefaultSigAlgForKey()`, which returns `SHA384withRSA` for RSA keys and has no PQC branch on JDK < 24.
- The signature file is named `*.RSA` — the extension is determined by the key algorithm. Every signed JAR in existence has a `.RSA` file whose signature is forgeable by a CRQC.
- A forged JAR signature enables supply-chain attacks: malicious bytecode in an APK or enterprise middleware that passes `jarsigner -verify`.
- Android APK v1 signing has no PQC specification. The APK Signature Scheme v3/v4 (used on Android 9+) uses ECDSA but also has no PQC path.
- Enterprise Java runs predominantly on LTS 11 or 17 (the vast majority of production deployments). JDK 24 added ML-DSA (JEP 497) but LTS 11/17 will never get it.

## migration status

JDK 24 (March 2025) added ML-DSA support via JEP 497. Blocked in practice by: Android APK spec has no PQC signing scheme, JVM ecosystem still largely on LTS 11/17, no CA infrastructure for PQC code-signing certificates.
