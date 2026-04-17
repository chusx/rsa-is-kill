// sap_rsa_sso.java
//
// SAP NetWeaver SSO 2.0 — RSA tokens and X.509 certificate authentication.
// Source: SAP Note 2028703 (X.509 client certificate authentication in NetWeaver)
//         SAP NetWeaver SSO 2.0 Administration Guide
//         SAP Identity Management (IdM) configuration documentation
//
// SAP NetWeaver is the runtime platform for SAP ERP, SAP S/4HANA, SAP BW,
// SAP PI/PO, and all ABAP/Java-based SAP products.
//
// SAP RSA usage:
//   1. X.509 certificate SSO: client certificates (RSA-2048) for ABAP and Java stacks
//   2. SAP Logon Tickets: signed JWS-like tokens with RSA keys
//   3. SAP NetWeaver SSO 2.0: Kerberos or X.509 for SSO across SAP landscape
//   4. SAP Web Dispatcher TLS: RSA-2048 server cert for HTTPS load balancing
//   5. SAP HANA TLS: RSA-2048 database connection certificates
//
// SAP deployment scale:
//   - Used by 77% of global transaction revenue processing (SAP claim)
//   - 440,000+ SAP customers worldwide
//   - SAP S/4HANA: ~24,000 live customers as of 2024
//   - Every Fortune 500 company either runs SAP or migrates from it
//   - German federal government (Bundesverwaltung), all major German manufacturers
//   - DoD enterprise resource planning (via SAP contracts)

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import sun.security.pkcs.PKCS7;

public class SapRsaSso {

    /**
     * SAP Logon Ticket — RSA-signed SSO token for SAP landscape.
     *
     * SAP generates a "Logon Ticket" that users can present to different SAP systems
     * for SSO. The ticket is signed with the issuing SAP system's RSA-2048 key.
     *
     * The public key is distributed to all accepting SAP systems via the SAP User
     * Management Engine (UME) or SAP ABAP trust relationship configuration.
     *
     * Ticket format (simplified):
     *   MYSAPSSO2={base64(SAPLOGONTICKET structure with RSA-2048 signature)}
     *
     * The SAPLOGONTICKET contains:
     *   - User ID (SAP username)
     *   - Issuer system ID (SAP system name)
     *   - Validity timestamps
     *   - RSA-2048 PKCS#1 v1.5 signature over the above fields
     */
    public static byte[] generateSapLogonTicket(String userId, String systemId,
                                                   PrivateKey issuerRsaKey,
                                                   X509Certificate issuerCert)
            throws Exception {

        // Construct ticket content
        String ticketContent = String.format(
            "User=%s&System=%s&ValidUntil=%d",
            userId, systemId, System.currentTimeMillis() + 3600000L
        );
        byte[] ticketBytes = ticketContent.getBytes("UTF-8");

        // RSA-2048 PKCS#1 v1.5 signature (SHA-256) over ticket content
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(issuerRsaKey);
        signer.update(ticketBytes);
        byte[] signature = signer.sign();

        // Combine: [ticket_len:2][ticket][sig_len:2][signature][cert_der]
        byte[] certDer = issuerCert.getEncoded();
        byte[] result = new byte[2 + ticketBytes.length + 2 + signature.length + certDer.length];
        // ... pack fields ...

        return Base64.getEncoder().encode(result);
        // Cookie: MYSAPSSO2={base64 result}
        // Any SAP system that trusts the issuer's RSA-2048 public key accepts this ticket
    }

    /**
     * verifySapLogonTicket() — verify RSA-2048 signature on SAP Logon Ticket.
     *
     * Called by SAP ICM (Internet Communication Manager) on every SSO request.
     * The accepting SAP system has the issuer's RSA-2048 public key in its
     * Certificate Store (transaction STRUST).
     *
     * An attacker who derives the issuer system's RSA private key can:
     *   - Forge SAP Logon Tickets for any user (including SAP_BASIS admin)
     *   - Authenticate to any SAP system in the landscape that trusts the issuer
     *   - Access SAP ERP (financial modules), SAP HR (personnel data), SAP CRM
     *
     * The MYSAPSSO2 ticket is transmitted as an HTTP cookie or HTTP header.
     * On TLS-protected SAP systems, the issuer's public key is in STRUST.
     * On non-TLS systems (still common in SAP landscapes), the ticket crosses the wire.
     */
    public static boolean verifySapLogonTicket(byte[] ticketBase64,
                                                 PublicKey issuerRsaPublicKey)
            throws Exception {

        byte[] ticket = Base64.getDecoder().decode(ticketBase64);

        // Parse: [ticket_len:2][ticket_content][sig_len:2][signature][cert_der]
        int ticketLen = ((ticket[0] & 0xFF) << 8) | (ticket[1] & 0xFF);
        byte[] ticketContent = new byte[ticketLen];
        System.arraycopy(ticket, 2, ticketContent, 0, ticketLen);

        int sigLen = ((ticket[2 + ticketLen] & 0xFF) << 8) | (ticket[3 + ticketLen] & 0xFF);
        byte[] signature = new byte[sigLen];
        System.arraycopy(ticket, 4 + ticketLen, signature, 0, sigLen);

        // Verify RSA-2048 PKCS#1 v1.5 SHA-256 signature
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(issuerRsaPublicKey);
        verifier.update(ticketContent);
        return verifier.verify(signature);
    }

    /**
     * sapX509ClientAuth() — X.509 certificate SSO in SAP NetWeaver.
     *
     * SAP NetWeaver (ABAP and Java stacks) supports X.509 client certificate
     * authentication via SAP NetWeaver SSO 2.0 or direct TLS client cert.
     *
     * The user's RSA-2048 certificate (from smart card, PKI, or client keystore)
     * is mapped to a SAP user via:
     *   a) Distinguished Name (DN) mapping in SICF/SU01
     *   b) Subject Alternative Name mapping
     *   c) Certificate thumbprint mapping
     *
     * SAP Web Dispatcher (reverse proxy) handles TLS termination with RSA-2048 cert.
     * The client cert CN/DN is forwarded to the ABAP/Java application server.
     *
     * An attacker who factors the user's RSA-2048 client cert can:
     *   - Authenticate to all SAP systems that accept that certificate
     *   - Run ABAP programs with the user's SAP authorizations
     *   - Access SAP financial data (FI/CO), HR data, procurement
     */
    public static String extractUserFromSapClientCert(X509Certificate clientCert) {
        // SAP maps certificate subject to SAP user ID
        // Common mapping: CN=JSMITH -> SAP user JSMITH
        String dn = clientCert.getSubjectDN().getName();

        // Parse CN from DN
        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                String cn = part.substring(3);
                // SAP user ID is typically the CN value
                // Or from SAP transaction SU01 X.509 certificate assignment
                return cn.toUpperCase();
            }
        }
        return null;
    }

    /**
     * sapHanaTlsConnect() — TLS connection to SAP HANA database with RSA cert.
     *
     * SAP HANA database uses TLS for JDBC/ODBC connections.
     * The HANA server certificate is RSA-2048 (issued by SAP Landscape Management).
     *
     * HANA stores financial data, HR records, and transactional data for S/4HANA.
     * The RSA-2048 server cert is what authenticates the HANA database to SAP apps.
     *
     * An attacker who factors the HANA server cert can:
     *   - MitM SAP application server -> HANA connections
     *   - Intercept and modify all database queries and results
     *   - Inject false financial records without touching SAP application layer
     */
    public static void connectHanaWithTls(String hanaHost, int hanaPort,
                                           String truststorePath, String truststorePassword)
            throws Exception {
        // HANA JDBC URL with TLS: jdbc:sap://{host}:{port}?encrypt=true&sslTrustStore={path}
        // The HANA server presents RSA-2048 certificate
        // truststorePath contains the HANA CA cert (RSA-2048 public key — CRQC input)
        String jdbcUrl = String.format(
            "jdbc:sap://%s:%d?encrypt=true&sslTrustStore=%s&sslTrustStorePassword=%s",
            hanaHost, hanaPort, truststorePath, truststorePassword
        );
        // Class.forName("com.sap.db.jdbc.Driver"); Connection conn = DriverManager.getConnection(jdbcUrl);
        System.out.println("HANA TLS URL: " + jdbcUrl);
    }
}
