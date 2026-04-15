/*
 * saml_response_sign.java
 *
 * Apache Santuario (xmlsec-java) signing path used by every Java SAML
 * IdP / federation gateway: Shibboleth IdP v5, Keycloak, Spring SAML,
 * OpenAM/ForgeRock AM, PingFederate. This shows the end-to-end flow of
 * a SAML 2.0 Response: build the assertion, canonicalize, compute the
 * reference digests, apply the Signature element with RSA-SHA256.
 */

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;

import org.w3c.dom.*;
import org.apache.xml.security.Init;

public class SamlResponseSign {

    static { Init.init(); }

    /**
     * Sign a SAML 2.0 Response (or Assertion) in-place.
     *
     * Algorithm set mandated by SAML profile (SSTC errata) + CSR deployed
     * reality: SignatureMethod = http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
     * DigestMethod    = http://www.w3.org/2001/04/xmlenc#sha256
     * Canonicalization = http://www.w3.org/2001/10/xml-exc-c14n#
     *
     * Production IdPs in 2026 are still dominantly RSA-2048 / RSA-3072
     * because the IDP signing cert is registered in SP-side metadata
     * and rotating requires federation-wide metadata resync.
     */
    public static void signResponse(Document doc,
                                     Element elementToSign,
                                     PrivateKey idpRsaKey,
                                     X509Certificate idpCert) throws Exception {
        XMLSignatureFactory fac =
            XMLSignatureFactory.getInstance("DOM");

        // Enveloped signature: the Signature lives inside the signed element.
        Reference ref = fac.newReference(
            "#" + elementToSign.getAttribute("ID"),
            fac.newDigestMethod(DigestMethod.SHA256, null),
            java.util.List.of(
                fac.newTransform(Transform.ENVELOPED,
                                  (TransformParameterSpec) null),
                fac.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#",
                                  (TransformParameterSpec) null)
            ),
            null, null
        );

        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                null),
            Collections.singletonList(ref)
        );

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(
            kif.newX509Data(java.util.List.of(idpCert))
        ));

        DOMSignContext dsc =
            new DOMSignContext(idpRsaKey, elementToSign);
        // Signature is inserted right after Issuer per SAML profile
        Node issuer = elementToSign.getElementsByTagNameNS(
            "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer").item(0);
        dsc.setNextSibling(issuer.getNextSibling());
        dsc.setDefaultNamespacePrefix("ds");

        XMLSignature xmlsig = fac.newXMLSignature(si, ki);
        xmlsig.sign(dsc);
    }

    // Calling context: typically invoked from Shibboleth IdP's
    // `SignAssertions` profile action or Keycloak's `SamlProtocol`
    // class. The `idpRsaKey` comes from the IdP keystore (JCEKS or
    // PKCS#11) and must match the <KeyDescriptor use="signing">
    // published in IdP metadata that every relying SP pins at trust-
    // establishment time.
}
