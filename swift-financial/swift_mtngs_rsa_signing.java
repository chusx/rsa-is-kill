/*
 * Illustrative code based on SWIFT MT/MX message signing and SWIFTNet PKI.
 *
 * SWIFT (Society for Worldwide Interbank Financial Telecommunication) processes
 * ~44 million financial messages per day, representing trillions of dollars
 * in transfers. Every SWIFT member institution (11,000+ banks in 200+ countries)
 * authenticates via SWIFTNet PKI — X.509 certificates for BIC identity.
 *
 * SWIFTNet PKI:
 *   - Root CA: SWIFT Root CA (RSA-4096)
 *   - Sub-CA: SWIFTNet CA (RSA-2048 or RSA-4096)
 *   - Bank certificates: RSA-2048 (issued per-institution, 2yr validity)
 *   - Used for: SWIFTNet Link TLS, Alliance Gateway auth, SWIFT API (API Portal)
 *
 * ISO 20022 MX messages (XML format, replacing MT):
 *   - Financial message signing uses XMLDSig (same as SAML): RSA-only
 *   - pacs.008 (credit transfers), pacs.009 (financial institution transfers)
 *   - camt.056 (payment cancellation), pain.001 (customer credit transfer)
 *   All signed with RSA-SHA256 per ISO 20022 security supplement
 *
 * No PQC algorithm is defined in SWIFTNet PKI or ISO 20022 security specs.
 * SWIFT has published awareness documents on quantum risk but no migration plan.
 */

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.RSAPrivateKey;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.*;
import org.w3c.dom.Document;

public class SWIFTMXMessageSigner {

    // SWIFTNet PKI certificate — RSA-2048, 2-year validity, per-BIC identity
    private static final String SWIFT_CA_KEYSTORE_TYPE  = "PKCS12";
    private static final String SWIFT_SIG_ALGORITHM     = "SHA256withRSA";   // RSA only in XMLDSig

    /**
     * Sign an ISO 20022 MX message (XML) with RSA-SHA256.
     * Used for: pacs.008 credit transfers, camt.053 bank statements,
     *           pain.001 customer payments, and all other MX message types.
     *
     * @param doc           The ISO 20022 MX message as a DOM Document
     * @param rsaPrivateKey The institution's SWIFTNet RSA-2048 private key
     * @param certificate   The institution's SWIFTNet X.509 certificate (RSA-2048)
     *
     * XMLDSig algorithm URIs are RSA-only:
     *   http://www.w3.org/2001/04/xmldsig-more#rsa-sha256  (most common)
     *   http://www.w3.org/2000/09/xmldsig#rsa-sha1         (legacy, still accepted)
     * No PQC URI is registered by W3C or ISO.
     */
    public void signMXMessage(Document doc,
                               RSAPrivateKey rsaPrivateKey,   // RSA-2048 SWIFTNet key
                               java.security.cert.X509Certificate certificate)
            throws Exception {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // RSA-SHA256 signature method (W3C XMLDSig)
        SignatureMethod sm = fac.newSignatureMethod(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            null
        );

        // Canonical XML 1.0 (C14N)
        CanonicalizationMethod cm = fac.newCanonicalizationMethod(
            CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null
        );

        // SHA-256 digest method
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA256, null);

        // Reference to the document root (enveloped signature)
        Reference ref = fac.newReference(
            "", dm,
            java.util.Collections.singletonList(
                fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)
            ),
            null, null
        );

        SignedInfo si = fac.newSignedInfo(cm, sm,
            java.util.Collections.singletonList(ref));

        // KeyInfo: embed the RSA-2048 X.509 certificate
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509d = kif.newX509Data(
            java.util.Collections.singletonList(certificate)
        );
        KeyInfo ki = kif.newKeyInfo(
            java.util.Collections.singletonList(x509d)
        );

        // Sign with RSA-2048 private key
        XMLSignature sig = fac.newXMLSignature(si, ki);
        DOMSignContext dsc = new DOMSignContext(rsaPrivateKey, doc.getDocumentElement());
        sig.sign(dsc);
        // Output: MX message with embedded RSA-2048 XMLDSig in <Signature> element
    }

    /*
     * SWIFT API Platform (2019+):
     * OAuth 2.0 with JWT — client_assertion uses RS256 (RSASSA-PKCS1-v1_5).
     * Same pattern as jwt-libjwt but in banking context.
     * The client's private signing key is the SWIFTNet RSA-2048 key.
     *
     * TARGET2 (ECB, European interbank real-time gross settlement):
     * Uses SWIFT messaging with XML signing. RSA-2048 certificates.
     * €400 billion/day processed. No PQC migration announced by ECB.
     *
     * Fedwire Funds Service (US Federal Reserve):
     * Uses proprietary format but TLS certificates for connectivity are RSA-2048.
     * ~$4 trillion/day processed.
     *
     * CHIPS (Clearing House Interbank Payments):
     * RSA-2048 for participant authentication.
     * ~$1.8 trillion/day.
     *
     * Harvest-Now-Decrypt-Later for finance:
     * Payment messages themselves are account numbers and amounts — not secret.
     * But authentication credentials (RSA keys) protect:
     *   - Routing of payments to correct accounts
     *   - Non-repudiation of payment instructions (legal evidence)
     *   - BIC identity (forging a bank's identity to initiate fraudulent transfers)
     */
}
