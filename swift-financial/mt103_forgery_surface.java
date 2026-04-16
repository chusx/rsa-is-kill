/*
 * mt103_forgery_surface.java
 *
 * SWIFT MT103 ("single customer credit transfer") message
 * builder used inside Alliance Access / SAG by a sending
 * bank. Shown here is the layer that RSA signs with the
 * bank's BIC RBAC certificate; signature is verified by
 * SWIFT's WebSphere MQ gateway and again by the beneficiary
 * bank's SAG on receipt.
 *
 * A factored BIC signing certificate (or the SWIFT RMA root)
 * permits an attacker to inject MT103 / MT202COV / MT900 / 910
 * messages into the correspondent-banking fabric with valid
 * LAU+SIGNATURE. Bangladesh Bank 2016 ($81M) generalized to
 * the entire installed base of any bank whose BIC key is
 * factored.
 *
 * This is intentionally not a working builder — the field
 * content is standardized (SWIFT User Handbook Category 1)
 * but the RSA dependency is what this file documents.
 */
package com.example.swift.mt103;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.UUID;

public final class Mt103Message {

    // Block 1: Basic header
    public String applicationId   = "F";            // FIN
    public String serviceId       = "01";           // general
    public String senderBic       = "DEUTDEFFXXX";  // 12-char LT
    public int    sessionNumber;
    public int    sequenceNumber;

    // Block 2: Application header
    public String receiverBic     = "CHASUS33XXX";
    public String messageType     = "103";

    // Block 3: User header (including 119:STP if applicable)
    public String uetr            = UUID.randomUUID().toString();

    // Block 4: text block (MT103 fields 20, 23B, 32A, 50K, 59, 70, 71A, ...)
    public String transactionRef;        // :20:  originator's ref
    public String bankOpCode = "CRED";   // :23B:
    public String valueDateCcyAmount;    // :32A: YYMMDDCCYAMOUNT
    public String ordCustomer;           // :50K:
    public String beneficiary;           // :59:
    public String remittanceInfo;        // :70:
    public String chargesCode = "SHA";   // :71A:

    // Block 5: trailer — MAC, PDM, CHK etc. The LAU (Local
    // Authentication) and SIGNATURE are SWIFTNet PKI artefacts
    // attached here by SAG before WebSphere MQ handoff.
    public String mac;                   // HMAC via LAU key
    public byte[] pkcs7Signature;        // RSA over Blk1-4 canonical

    /* Canonical form over which RSA signs. SWIFT User Handbook
     * specifies field ordering and SOH/STX separators; we list
     * the fields in required order. */
    private byte[] canonicalize() {
        StringBuilder sb = new StringBuilder();
        sb.append('{').append("1:").append(applicationId)
          .append(serviceId).append(senderBic)
          .append(String.format("%04d", sessionNumber))
          .append(String.format("%06d", sequenceNumber)).append('}');
        sb.append('{').append("2:").append('I').append(messageType)
          .append(receiverBic).append('N').append('}');
        sb.append('{').append("3:").append("{121:").append(uetr).append("}}");
        sb.append('{').append("4:\r\n")
          .append(":20:").append(transactionRef).append("\r\n")
          .append(":23B:").append(bankOpCode).append("\r\n")
          .append(":32A:").append(valueDateCcyAmount).append("\r\n")
          .append(":50K:").append(ordCustomer).append("\r\n")
          .append(":59:").append(beneficiary).append("\r\n")
          .append(":70:").append(remittanceInfo).append("\r\n")
          .append(":71A:").append(chargesCode).append("\r\n-}");
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    public void sign(KeyStore ks, String alias, char[] pin)
            throws Exception {
        PrivateKey priv = (PrivateKey) ks.getKey(alias, pin);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(priv);
        s.update(canonicalize());
        this.pkcs7Signature = s.sign();                // RSA-2048/4096
    }

    public boolean verify(X509Certificate signerCert) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(signerCert);
        s.update(canonicalize());
        return s.verify(pkcs7Signature);
    }
}

/*
 * =========================================================
 *  RMA / Relationship Management Authorization
 *
 *  Before an MT103 is accepted by the receiver, SAG checks
 *  that the sender-BIC has an RMA relationship authorizing
 *  MT103 from that sender. The RMA authorization ITSELF is
 *  an RSA-signed SWIFTNet message ("Subject Rule").
 *  Factored SWIFTNet PKI root -> attacker mints RMA from
 *  any BIC to any other BIC.
 * =========================================================
 */
final class RmaSubjectRule {
    String allowedFromBic;
    String allowedToBic;
    String[] allowedMtTypes;    // {"103","202","202COV", ...}
    Instant notBefore;
    Instant notAfter;
    byte[]  swiftnetPkiSignature;    // RSA-2048
    byte[]  swiftnetPkiCertDer;      // chains to SWIFTNet Root CA
}

/*
 * ---- Break surface ---------------------------------------
 *
 *  Sender-BIC signing cert factored:
 *    Forge MT103 with valid SAG signature from that BIC.
 *    Beneficiary bank's SAG accepts; funds debit correspondent
 *    nostro and book to any beneficiary account. Recoverable
 *    only by reversal — which requires the sender bank to
 *    cooperate and admit. Several to tens of millions of $
 *    per event; daylight overdraft caps the single-event size
 *    but volume is trivially scalable.
 *
 *  SWIFTNet PKI Root factored:
 *    Mint any BIC's operator/RBAC/LAU cert. Mass injection
 *    across the fabric; SWIFT has to reissue every
 *    participant's PKI — a multi-year, multi-thousand-bank
 *    coordinated refresh with degraded operations in between.
 *
 *  Detection: SAG sanctions filter + fraud-pattern analytics
 *  catch some amounts/beneficiaries but not cryptographic
 *  authenticity. Once signed, the message is "good" by
 *  SWIFTNet rules and the receiver is obliged to settle.
 * --------------------------------------------------------- */
