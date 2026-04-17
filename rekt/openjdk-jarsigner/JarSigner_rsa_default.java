/*
 * Source: OpenJDK - https://github.com/openjdk/jdk
 * File:   src/jdk.jartool/share/classes/jdk/security/jarsigner/JarSigner.java
 * License: GPLv2 with Classpath Exception
 *
 * Relevant excerpt: RSA is the default JAR signing algorithm.
 * jarsigner is used to sign:
 *   - Android APKs (v1 scheme, still required for compatibility)
 *   - Java EE / Jakarta EE application archives
 *   - OSGi bundles
 *   - Maven artifacts (via GPG plugin, but jarsigner for .jar integrity)
 *
 * The signed .RSA entry inside META-INF/ of every JAR contains an RSA
 * signature over the manifest hash.  A CRQC can forge this signature,
 * enabling supply-chain attacks: malicious bytecode in a "signed" JAR
 * that passes jarsigner -verify.
 *
 * OpenJDK 24 added ML-DSA support (JEP 497), but:
 *   - Enterprise Java is predominantly on LTS 11 or 17 (no ML-DSA).
 *   - Android's APK v1 signing has no PQC equivalent in any released spec.
 *   - The JVM that verifies the JAR must also support ML-DSA.
 */

public final class JarSigner {

    /**
     * Returns the default signature algorithm for the given private key.
     * For RSA keys: SHA384withRSA (or SHA512withRSA for keys > 7680 bits).
     * Result is stored in META-INF/*.RSA inside the JAR.
     *
     * No PQC algorithm (ML-DSA / SLH-DSA) is returned here on any
     * JDK version < 24, and JDK 24 support requires explicit opt-in.
     */
    public static String getDefaultSignatureAlgorithm(PrivateKey key) {
        return SignatureUtil.getDefaultSigAlgForKey(
                Objects.requireNonNull(key));
        /*
         * SignatureUtil.getDefaultSigAlgForKey() returns:
         *   RSA key  -> "SHA384withRSA"  (key <= 7680 bits)
         *            -> "SHA512withRSA"  (key >  7680 bits)
         *   EC  key  -> "SHA384withECDSA" etc.
         *   DSA key  -> "SHA256withDSA"
         *
         * On JDK < 24 there is no case for ML-DSA keys because
         * java.security.interfaces.MLDSAKey does not exist.
         */
    }

    /**
     * Builder.build() wires the private key to its default algorithm.
     * The resulting JarSigner will write a .RSA (or .EC / .DSA) file
     * into META-INF/ of the target JAR.
     */
    public static class Builder {
        public Builder(PrivateKey privateKey, CertPath certPath) {
            Objects.requireNonNull(privateKey);
            Objects.requireNonNull(certPath);
            // Derive algorithm from key type - no PQC branch on JDK < 24
            this.sigAlg = getDefaultSignatureAlgorithm(privateKey);
            // Verify key/cert algorithm compatibility
            SignatureUtil.checkKeyAndSigAlgMatch(privateKey, this.sigAlg);
        }
    }
}
