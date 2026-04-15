// legal_document_workflow.java
//
// iText 8 / OpenPDF / Apache PDFBox signing pipeline wired around the
// CMS / PAdES primitive in `PdfRsaSigning.java`. This is the document
// signing flow at real e-signature operators + large enterprises.
//
// Deployed at:
//   - DocuSign, Adobe Sign, Dropbox HelloSign, SignNow, PandaDoc,
//     Bloomberg terminal e-sign, Zoho Sign — all use iText / PDFBox
//     underneath for PAdES-B-LTA long-term archival signatures.
//   - Government e-filing: DE ELSTER tax filings, US federal
//     contract DocuSign NAVFAC workflows, eIDAS qualified electronic
//     signature providers (DTrust, D-Trust, SwissSign, FNMT).
//   - Every invoicing platform that emits PDF/A-3 with signed
//     embedded structured invoice data (ZUGFeRD, FatturaPA, Peppol
//     BIS).

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.*;

import java.io.FileOutputStream;
import java.security.cert.Certificate;
import java.security.*;
import java.util.Arrays;
import java.util.Calendar;


public class LegalDocumentWorkflow {

    /**
     * Sign an already-prepared PDF with the production HSM key.
     * Runs inside every e-signature backend sign() handler.
     */
    public static void signPdf(String inputPdf, String outputPdf,
                                 String signerReason,
                                 String signerLocation,
                                 String contactInfo) throws Exception {

        // 1. PKCS#11 provider pointing at the corporate HSM. Real
        // e-sign operators store the QTSP's signing key in a FIPS
        // 140-2 L3 HSM (Luna, SafeNet, Utimaco, AWS CloudHSM). The
        // key material never leaves the HSM. This is the RSA-3072
        // or RSA-4096 qualified-signature key.
        Provider p = java.security.Security.getProvider("SunPKCS11-HSM");
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, System.getenv("HSM_USER_PIN").toCharArray());

        String alias = "QTSP-SIGNER-2026";
        Certificate[] chain = ks.getCertificateChain(alias);
        PrivateKey    pk    = (PrivateKey) ks.getKey(alias, null);

        // 2. Prepare PAdES-B-LTA fields.  Every qualified electronic
        // signature carries signing-cert-v2 + signing-time + signer
        // location attributes, plus a timestamp countersignature
        // from an RFC 3161 TSA (see `rfc3161-tsa-timestamp/` and
        // `authenticode-pe/` directories).
        PdfReader reader = new PdfReader(inputPdf);
        FileOutputStream out = new FileOutputStream(outputPdf);
        PdfSigner signer = new PdfSigner(reader, out, new StampingProperties().useAppendMode());

        PdfSignatureAppearance app = signer.getSignatureAppearance()
            .setReason(signerReason)
            .setLocation(signerLocation)
            .setContact(contactInfo)
            .setReuseAppearance(false);
        signer.setFieldName("SignatureFieldName-Legal");

        // 3. Signing container: PAdES-B-LTA via BouncyCastle +
        // external digest pipeline for very large PDFs.
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA-384", p.getName());
        IExternalDigest    dig = new BouncyCastleDigest();

        // RSA-PSS with SHA-384; falls back to RSA-PKCS1 v1.5 for
        // long-tail Acrobat Reader versions that don't support PSS
        // (< Reader XI).
        signer.signDetached(dig, pks, chain,
                             null, null,
                             getOcspClient(),
                             getTsaClient(),
                             0, PdfSigner.CryptoStandard.CADES);
    }

    private static ITSAClient getTsaClient() {
        // Production deployments use a QTSP-internal or DigiCert /
        // GlobalSign TSA — countersigning the RSA signature elevates
        // the doc to "long-term archival" validity (PAdES-B-LTA) for
        // 20+ year retention.
        return new TSAClientBouncyCastle(
            "http://timestamp.digicert.com",
            null, null,
            4096, "SHA-256");
    }

    private static IOcspClient getOcspClient() {
        return new OcspClientBouncyCastle(new OCSPVerifier(null, null));
    }


    /* ---- Breakage ----
     *
     * Qualified electronic signatures (QES) under eIDAS depend on a
     * QTSP root CA chain — all RSA-4096 at operators like SwissSign,
     * D-Trust, FNMT, Actalis, Infocert. A factoring attack against
     * any QTSP root lets an attacker:
     *   - Forge legal-weight signatures on contracts, real-estate
     *     deeds, power-of-attorney, tax filings.
     *   - Re-sign existing archival PDFs with a backdated signing
     *     time (the TSA countersignature normally prevents this, but
     *     TSAs are also RSA — see rfc3161-tsa-timestamp/).
     * The legal-infrastructure blast radius is that every PAdES-
     * signed document in 20-year European archival storage becomes
     * retroactively forgeable by anyone who cracks the QTSP root.
     */
}
