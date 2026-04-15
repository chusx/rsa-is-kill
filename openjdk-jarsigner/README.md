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

## impact

JAR signing is how the JVM verifies that bytecode comes from who it says it does. every signed JAR in existence has a .RSA file whose signature is forgeable once you have a factoring oracle.

- forge a JAR signature for any published artifact and distribute it as the real thing. it passes jarsigner -verify as the original signer. supply chain attack with cryptographic cover
- Maven Central has millions of artifacts signed with RSA keys. forge signatures for popular libraries and distribute malicious versions that the JVM accepts as authenticated
- Android APK signing v1 scheme uses JAR signing. RSA-signed APKs from before the v2/v3 migration are vulnerable
- enterprise Java runs mostly on LTS 11 or 17. JDK 24 added ML-DSA via JEP 497 but LTS 11 and 17 will never get it. the vast majority of production JVMs are permanently RSA-only for JAR signature validation
