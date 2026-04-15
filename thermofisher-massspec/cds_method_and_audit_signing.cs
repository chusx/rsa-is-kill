/*
 * cds_method_and_audit_signing.cs
 *
 * Chromatography Data System (CDS) — method-file signing, audit-
 * trail entry signing, and batch-release electronic-signature
 * orchestration. Pattern matches Thermo Chromeleon, Waters Empower,
 * Agilent OpenLab CDS, SCIEX SCIEX OS, Shimadzu LabSolutions.
 *
 * Runs on the CDS application server (.NET / C# over SQL Server).
 * This compiles under .NET; file carries .cs extension so the
 * flavour is clear.
 */

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Labs.Cds.Signing
{
    /*
     * 21 CFR Part 11 §11.70 requires the e-signature be linked to
     * the record such that it cannot be detached, copied, or
     * transferred to falsify another record. We do this by computing
     * the signature over (record_hash || signer_meta || reason).
     */

    public static class MethodFileSigning
    {
        /* Sign a saved method file on approval. The signing cert is
         * the analyst's personal issued by the enterprise PKI (the
         * user authenticated with smart card / PIV at the CDS
         * client). The signature is stored beside the method blob. */
        public static SignedCms SignMethodOnApproval(
            byte[] methodBlob,
            X509Certificate2 analystCert,
            string meaning,           /* "AUTHOR", "REVIEWER", "APPROVER" */
            string reason)            /* free-text justification */
        {
            var contentBytes = BuildSignedContent(methodBlob, meaning, reason);
            var content = new ContentInfo(contentBytes);
            var cms = new SignedCms(content, detached: false);
            var signer = new CmsSigner(analystCert)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") /* SHA-256 */
            };
            /* Signature algorithm falls out of the cert's key — the
             * enterprise PKI issues RSA-2048 / RSA-3072 to every
             * analyst. */
            signer.SignedAttributes.Add(
                new Pkcs9SigningTime(DateTime.UtcNow));
            signer.SignedAttributes.Add(
                new AsnEncodedData("1.3.6.1.4.1.99999.11.70.meaning",
                                   System.Text.Encoding.UTF8.GetBytes(meaning)));
            cms.ComputeSignature(signer);
            return cms;
        }

        private static byte[] BuildSignedContent(
            byte[] methodBlob, string meaning, string reason)
        {
            using var ms = new System.IO.MemoryStream();
            ms.Write(methodBlob, 0, methodBlob.Length);
            var tail = System.Text.Encoding.UTF8.GetBytes(
                $"|meaning={meaning}|reason={reason}|utc={DateTime.UtcNow:O}");
            ms.Write(tail, 0, tail.Length);
            return ms.ToArray();
        }

        public static bool VerifyMethodSignature(
            byte[] signedCms, byte[] expectedMethodBlob,
            X509Certificate2 enterpriseCa)
        {
            var cms = new SignedCms();
            cms.Decode(signedCms);
            /* Chain-verify signer cert to enterprise CA issued by
             * lab IT (backed by HSM — nCipher, Thales, Utimaco). */
            var extraStore = new X509Certificate2Collection(enterpriseCa);
            cms.CheckSignature(extraStore, verifySignatureOnly: false);
            /* Body equality — the signed record must actually be
             * the method we think it is. */
            var content = cms.ContentInfo.Content;
            if (content.Length < expectedMethodBlob.Length) return false;
            for (int i = 0; i < expectedMethodBlob.Length; i++)
                if (content[i] != expectedMethodBlob[i]) return false;
            return true;
        }
    }


    /*
     * Audit-trail entry signing. Part 11 audit trails must be
     * secure + computer-generated and must capture: who / when /
     * what / old-value / new-value / reason. Entries are hash-
     * chained AND each is RSA-signed by the application server's
     * system cert (not the analyst's — see rationale below).
     */

    public record AuditEntry(
        long Id, DateTime UtcTs, string UserUpn, string RecordUri,
        string Action, string FieldPath,
        string OldValue, string NewValue, string Reason,
        byte[] PrevEntryHash);

    public static class AuditTrailSigning
    {
        public static byte[] ComputeEntryHash(AuditEntry e)
        {
            using var sha = SHA256.Create();
            var payload = System.Text.Encoding.UTF8.GetBytes(
                $"{e.Id}|{e.UtcTs:O}|{e.UserUpn}|{e.RecordUri}|"
              + $"{e.Action}|{e.FieldPath}|{e.OldValue}|{e.NewValue}|"
              + $"{e.Reason}");
            using var ms = new System.IO.MemoryStream();
            ms.Write(payload, 0, payload.Length);
            ms.Write(e.PrevEntryHash, 0, e.PrevEntryHash.Length);
            return sha.ComputeHash(ms.ToArray());
        }

        /* The application server signs — NOT the analyst — because
         * entries are computer-generated and must be written on
         * every field change even by admins whose identity is
         * already captured in the Action row. System cert is an
         * RSA-3072 leaf from enterprise PKI, private key in HSM. */
        public static byte[] SignEntry(AuditEntry e, RSA serverSigningKey)
        {
            var h = ComputeEntryHash(e);
            return serverSigningKey.SignHash(
                h, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        public static bool VerifyEntry(
            AuditEntry e, byte[] sig, RSA serverSigningPubKey)
        {
            var h = ComputeEntryHash(e);
            return serverSigningPubKey.VerifyHash(
                h, sig, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }
    }


    /*
     * Batch-release electronic signature — the QA approval that
     * releases a pharma manufacturing batch.
     *
     * Per 21 CFR 211.188 + ICH Q7 §6.7, the batch record must be
     * reviewed and approved by QA before release. In computerised
     * systems this is an e-signature event with EU Annex 11
     * qualifying attributes.
     */
    public static class BatchRelease
    {
        public static SignedCms SignBatchRelease(
            string batchNumber,
            byte[] batchRecordPdf,
            X509Certificate2 qaSignerCert)
        {
            /* Dual-sign pattern (EU Annex 11 clause 12.4 recommends
             * two-person release for high-risk products): caller
             * orchestrates by invoking this twice with two different
             * QA signers. Each signature is chained into the
             * CMS SignedData. */
            var content = new ContentInfo(batchRecordPdf);
            var cms = new SignedCms(content, detached: true);
            var signer = new CmsSigner(qaSignerCert)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
                SignaturePadding = RSASignaturePadding.Pss
            };
            signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            signer.SignedAttributes.Add(
                new AsnEncodedData("1.3.6.1.4.1.99999.BR.batch",
                    System.Text.Encoding.UTF8.GetBytes(batchNumber)));
            cms.ComputeSignature(signer);
            return cms;
        }
    }
}


/* ---- Breakage ---------------------------------------------
 *
 *   Enterprise-PKI analyst-cert issuing CA factored:
 *     - Attacker mints analyst certs, signs forged method-file
 *       approvals, signs false batch-release approvals. Falsified
 *       pharma batch records directly threaten patient safety
 *       (contaminated / mislabelled product released).
 *
 *   System audit-trail signing key factored:
 *     - Entire Part 11 audit trail reconstructable after-the-fact
 *       by the attacker; FDA 483 guarantee on every inspection
 *       at every site using the platform.
 *
 *   Vendor instrument firmware-signing root factored:
 *     - Silent calibration bias in instrument firmware; TDM,
 *       tox-screen, DUI, doping, forensic results wrong at
 *       population scale.
 *
 *   eCTD / FDA ESG trust-anchor factored:
 *     - Integrity of drug-submission chain of custody in
 *       question for every active NDA / BLA.
 */
