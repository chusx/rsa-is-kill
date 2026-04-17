/*
 * xmlsec_rsa_sign.java
 *
 * Apache Santuario (XML Security for Java) — RSA in XML Digital Signatures.
 * Repository: Apache SVN — https://svn.apache.org/repos/asf/santuario/xml-security-java/
 * Also mirrored at: https://gitbox.apache.org/repos/asf/santuario-java.git
 *
 * Apache Santuario implements the W3C XML Digital Signature (XMLDSig) and
 * XML Encryption standards. It is used by:
 *
 *   - Apache WSS4J — WS-Security (SOAP message signing in enterprise Java)
 *   - Apache CXF — JAX-WS web services framework (used by healthcare HL7 v3, financial SOAP APIs)
 *   - Spring-WS — Spring Framework SOAP support
 *   - Apache Axis2 — SOAP engine
 *   - SAML implementations (Spring Security SAML, Shibboleth IdP, OpenAM)
 *   - US federal e-Government (many agencies use SOAP/WS-Security with XMLDSig)
 *   - HL7 SOAP messaging (healthcare EHR interoperability)
 *
 * The W3C XMLDSig standard (https://www.w3.org/TR/xmldsig-core/) defines RSA-SHA1
 * and RSA-SHA256 signature algorithm URIs. There is no ML-DSA URI registered.
 * The W3C has not published a PQC XMLDSig standard.
 */

package org.apache.xml.security.signature;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * XMLSignature — creates and verifies XML Digital Signatures.
 *
 * The W3C XMLDSig algorithms supported by Apache Santuario:
 *   SHA1withRSA    = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
 *   SHA256withRSA  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
 *   SHA384withRSA  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
 *   SHA512withRSA  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
 *   RSA-PSS        = "http://www.w3.org/2007/05/xmldsig-more#rsa-pss"
 *   RSA-OAEP       = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
 *
 * All of these are RSA. There is no ML-DSA XMLDSig URI anywhere in the W3C registry.
 *
 * Source: santuario-java/src/main/java/org/apache/xml/security/signature/XMLSignature.java
 */
public class XMLSignature {

    /** RSA-SHA256 algorithm URI — typical for WS-Security in 2020s enterprise Java */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA256 =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /** RSA-SHA1 — legacy, still common in deployed SAML and HL7 systems */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA1 =
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /** RSA-OAEP encryption (XML Encryption standard) */
    public static final String ALGO_ID_KEYTRANSPORT_RSAOAEP =
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    private SignatureAlgorithm sa;
    private Element signatureElement;
    private Document doc;

    /**
     * sign() — signs the XML document with the given RSA private key.
     *
     * This is called by WS-Security, SAML IdP, and e-Government signing services
     * to digitally sign SOAP messages, SAML assertions, and XML documents.
     *
     * Source: XMLSignature.java sign(Key signingKey)
     */
    public void sign(Key signingKey) throws XMLSignatureException {
        if (!(signingKey instanceof RSAPrivateKey)) {
            // Also accepts DSAPrivateKey and ECPrivateKey, but RSA is by far
            // the most common in enterprise Java WS-Security deployments
            throw new XMLSignatureException("Key must be RSA for XMLDSig");
        }

        // Canonicalize the SignedInfo element (C14N normalizes whitespace, namespace prefixes)
        byte[] signedInfoC14N = sa.getBytesToSign(signatureElement);

        // Compute RSA PKCS#1 v1.5 signature over the canonicalized SignedInfo
        // sa.engineSign() calls java.security.Signature.getInstance("SHA256withRSA")
        // and ultimately JCE's RSA implementation (SunRsaSign or BouncyCastle provider)
        byte[] jcebytes = sa.sign();  // SHA256withRSA signature

        // Encode and insert the signature value into the XML
        Base64.setDocument(doc);
        Element signatureValueElem = XMLUtils.createElementInSignatureSpace(
            doc, Constants._TAG_SIGNATUREVALUE);
        signatureValueElem.appendChild(
            doc.createTextNode(Base64.encode(jcebytes))
        );
        signatureElement.insertBefore(signatureValueElem, /*KeyInfo*/ null);
    }

    /**
     * checkSignatureValue() — verifies an RSA XMLDSig signature.
     *
     * Called by SAML service providers (SP), WS-Security policy enforcement,
     * and any XML-verifying component. The RSA public key is extracted from
     * the <KeyInfo> element embedded in the signature (or from a keystore).
     *
     * Source: XMLSignature.java checkSignatureValue(Key pk)
     */
    public boolean checkSignatureValue(Key pk) throws XMLSignatureException {
        if (!(pk instanceof RSAPublicKey)) {
            throw new XMLSignatureException("Public key must be RSA");
        }

        // Recalculate the digest of the SignedInfo
        byte[] signedInfoC14N = sa.getBytesToSign(signatureElement);

        // Extract the SignatureValue bytes from the XML
        byte[] sigBytes = getSignatureValue();

        // Verify: RSAPublicKey.verify(SHA256(signedInfoC14N), sigBytes)
        // sa.engineVerify() -> java.security.Signature.verify() -> SunRsaSign or BC
        return sa.verify(sigBytes);
    }
}

/**
 * WS-Security usage — how Apache WSS4J uses Santuario for SOAP message signing.
 *
 * Source: wss4j/ws-security-dom/src/main/java/org/apache/wss4j/dom/message/WSSecSignature.java
 *
 * Enterprise SOAP services (banking APIs, healthcare HL7 v3, government SOAP,
 * insurance ACORD XML) sign SOAP messages with WS-Security using RSA-SHA256.
 * The SignatureAlgorithm URI is hardcoded as rsa-sha256 or rsa-sha1 in the
 * WS-Policy attached to the service.
 */
class WSSecSignature {

    // From WSS4J WSSecSignature.java — the default signing algorithm
    private String sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;

    /**
     * build() creates a WS-Security header with an RSA signature over
     * the specified SOAP body elements.
     *
     * In financial SOAP APIs (ISO 20022 SOAP, SWIFT FileAct), this is how
     * individual payment messages are authenticated before transmission.
     * The RSA certificate is issued by the bank's enterprise CA (see adcs-windows/).
     *
     * signingKey is an RSAPrivateKey from the bank's Java keystore (.jks or .p12).
     */
    public Document build(Document doc, Crypto crypto, WSSecHeader header)
            throws WSSecurityException {

        // Add BST (BinarySecurityToken) — the X.509 RSA certificate
        bstToken = new X509Security(doc);
        bstToken.setX509Certificate(certs[0]);  // RSA-2048 cert

        // Create the ds:Signature element pointing to the SOAP body
        sig = new XMLSignature(doc, null,
                               sigAlgo,  // "...#rsa-sha256"
                               Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        // Sign the SOAP body with the RSA private key
        // The RSA-2048 private key in the JKS/PKCS12 keystore is the attack surface
        sig.sign(signingKey);

        return doc;
    }
}
