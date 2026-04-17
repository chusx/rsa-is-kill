      *----------------------------------------------------------------*
      * ICSF_RSA_COBOL.CBL                                            *
      *                                                                *
      * IBM z/OS ICSF (Integrated Cryptographic Service Facility)     *
      * RSA key generation, signing, and decryption via COBOL         *
      * callable services (CSF verbs).                                *
      *                                                                *
      * Reference: IBM z/OS Cryptographic Services ICSF               *
      *   Application Programmer's Guide (SA22-7522)                  *
      *   CSNDRSA - Digital Signature Generate                        *
      *   CSNDPKE - PKA Encrypt (RSA key wrap / encryption)          *
      *   CSNDPKD - PKA Decrypt (RSA key unwrap / decryption)        *
      *   CSNDPKB - PKA Public Key Token Build                       *
      *                                                                *
      * IBM z/OS mainframes run an estimated 30 billion transactions   *
      * per day across banking, insurance, government, and retail.    *
      * Nearly every COBOL application on z/OS that does cryptography *
      * calls ICSF. The RSA key management is handled by the CEX      *
      * (Crypto Express) coprocessor card — hardware RSA acceleration *
      * baked into the physical server. The CEX7S and CEX8S cards     *
      * support RSA-4096 but have no ML-DSA or ML-KEM capability.    *
      *                                                                *
      * There is no ICSF callable service for any NIST PQC algorithm. *
      * IBM has published z/OS 3.1 notes about "PQC exploration" but  *
      * no ICSF PQC callable service has been shipped or scheduled.   *
      *----------------------------------------------------------------*
       IDENTIFICATION DIVISION.
       PROGRAM-ID.  ICSFRSA.
       AUTHOR.      IBMSAMPLE.

       ENVIRONMENT DIVISION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

      *----------------------------------------------------------------*
      * ICSF callable service common parameters                        *
      *----------------------------------------------------------------*
       01  WS-RETURN-CODE         PIC S9(9) COMP VALUE ZERO.
       01  WS-REASON-CODE         PIC S9(9) COMP VALUE ZERO.
       01  WS-EXIT-DATA-LEN       PIC S9(9) COMP VALUE ZERO.
       01  WS-EXIT-DATA           PIC X(4)  VALUE SPACES.
       01  WS-RULE-ARRAY-LEN      PIC S9(9) COMP.
       01  WS-RULE-ARRAY          PIC X(80).

      *----------------------------------------------------------------*
      * RSA key token storage                                          *
      * ICSF PKA key tokens are binary structures containing the       *
      * RSA key material (modulus n, exponents d and e) for private    *
      * keys, or (n, e) for public keys.                               *
      *----------------------------------------------------------------*
       01  WS-PRIVATE-KEY-TOKEN.
           05  WS-PRIV-KEY-TOKEN-LEN  PIC S9(9) COMP VALUE 2500.
           05  WS-PRIV-KEY-TOKEN      PIC X(2500).

       01  WS-PUBLIC-KEY-TOKEN.
           05  WS-PUB-KEY-TOKEN-LEN   PIC S9(9) COMP VALUE 2500.
           05  WS-PUB-KEY-TOKEN       PIC X(2500).

      *----------------------------------------------------------------*
      * RSA key generation parameters                                  *
      *----------------------------------------------------------------*
       01  WS-RSA-KEY-SIZE        PIC S9(9) COMP VALUE 2048.
       *    2048 is the default. Some financial apps use 4096.
       *    IBM CEX hardware supports RSA-512 through RSA-4096.
       *    No PQC algorithm (ML-DSA, ML-KEM) is supported.

      *----------------------------------------------------------------*
      * Digital signature buffers                                      *
      *----------------------------------------------------------------*
       01  WS-HASH-RULE.
           05  WS-HASH-RULE-LEN   PIC S9(9) COMP VALUE 8.
           05  WS-HASH-RULE-DATA  PIC X(8) VALUE 'SHA-256 '.
           *    Hash algorithm rule: SHA-256 (or SHA-1 for legacy apps)

       01  WS-MESSAGE-HASH.
           05  WS-HASH-LEN        PIC S9(9) COMP VALUE 32.
           05  WS-HASH-DATA       PIC X(32).
           *    SHA-256 digest of the message to be signed

       01  WS-SIGNATURE.
           05  WS-SIG-LEN         PIC S9(9) COMP VALUE 256.
           05  WS-SIG-DATA        PIC X(256).
           *    RSA-2048 signature output = 256 bytes
           *    RSA-4096 signature output = 512 bytes

       01  WS-SIG-RULE.
           05  WS-SIG-RULE-LEN    PIC S9(9) COMP VALUE 16.
           05  WS-SIG-RULE-DATA   PIC X(16) VALUE
               'PKCS-1.1        '.
           *    PKCS#1 v1.5 padding. Legacy apps also use 'ZERO-PAD'

      *----------------------------------------------------------------*
      * PKA Encrypt / Decrypt buffers (RSA key wrapping)              *
      * Banks use RSA-OAEP to wrap DES/AES session keys               *
      *----------------------------------------------------------------*
       01  WS-PKA-ENCRYPT-RULE.
           05  WS-PKA-ENC-LEN     PIC S9(9) COMP VALUE 16.
           05  WS-PKA-ENC-DATA    PIC X(16) VALUE 'PKCS-OAEP       '.

       01  WS-CLEARTEXT-KEY.
           05  WS-CLRKEY-LEN      PIC S9(9) COMP VALUE 32.
           05  WS-CLRKEY-DATA     PIC X(32).
           *    AES-256 or 3DES key to be wrapped with RSA

       01  WS-CIPHERTEXT.
           05  WS-CIPHER-LEN      PIC S9(9) COMP VALUE 512.
           05  WS-CIPHER-DATA     PIC X(512).

       PROCEDURE DIVISION.

      *----------------------------------------------------------------*
      * Step 1: Generate an RSA-2048 keypair                           *
      * Callable service: CSNDPKB (PKA Public Key Token Build) then   *
      * CSNBKTB2 (Key Token Build 2) for the private key              *
      *                                                                *
      * In production banking applications, the RSA private key is    *
      * generated inside the CEX coprocessor and never leaves it in   *
      * cleartext. The key token stores an encrypted form of the key. *
      *----------------------------------------------------------------*
       GEN-RSA-KEY.
           MOVE 2048 TO WS-RSA-KEY-SIZE

           *    CSNDPKB builds the public key token from supplied n,e
           *    For generation, CSNDPKG (PKA Key Generate) is used:
           CALL 'CSNDPKG' USING
               WS-RETURN-CODE
               WS-REASON-CODE
               WS-EXIT-DATA-LEN
               WS-EXIT-DATA
               WS-RULE-ARRAY-LEN
               WS-RULE-ARRAY
               WS-RSA-KEY-SIZE        *> key size in bits: 2048
               WS-PRIVATE-KEY-TOKEN   *> output: encrypted private key token
               WS-PUBLIC-KEY-TOKEN    *> output: public key token

           IF WS-RETURN-CODE NOT = ZERO
               DISPLAY 'CSNDPKG FAILED RC=' WS-RETURN-CODE
                       ' RSN=' WS-REASON-CODE
               STOP RUN
           END-IF.

      *----------------------------------------------------------------*
      * Step 2: Generate RSA-2048 digital signature (CSNDRSA)         *
      *                                                                *
      * CSNDRSA is the primary ICSF signing callable service.        *
      * Called millions of times per day in production banking COBOL  *
      * for: SWIFT message signing, payment authorization,           *
      * ACH transaction authentication, regulatory filing signatures. *
      *----------------------------------------------------------------*
       SIGN-MESSAGE.
           MOVE 16 TO WS-SIG-RULE-LEN

           *    CSNDRSA - Digital Signature Generate
           *    Computes: sig = msg_hash ^ d mod n
           *    where d is the RSA private exponent from the key token
           CALL 'CSNDRSA' USING
               WS-RETURN-CODE
               WS-REASON-CODE
               WS-EXIT-DATA-LEN
               WS-EXIT-DATA
               WS-SIG-RULE-LEN        *> 16 = length of rule array
               WS-SIG-RULE-DATA       *> 'PKCS-1.1' = PKCS#1 v1.5
               WS-HASH-LEN            *> 32 for SHA-256
               WS-HASH-DATA           *> SHA-256 hash of message
               WS-PRIV-KEY-TOKEN-LEN
               WS-PRIV-KEY-TOKEN      *> RSA-2048 private key token
               WS-SIG-LEN             *> 256 bytes output buffer
               WS-SIG-DATA            *> output: RSA-2048 signature

           IF WS-RETURN-CODE NOT = ZERO
               DISPLAY 'CSNDRSA FAILED RC=' WS-RETURN-CODE
               STOP RUN
           END-IF

           DISPLAY 'RSA-2048 SIGNATURE GENERATED OK'.

      *----------------------------------------------------------------*
      * Step 3: RSA-OAEP key encryption (CSNDPKE)                     *
      *                                                                *
      * Banks and payment processors use RSA-OAEP to wrap AES/DES    *
      * session keys for inter-system key exchange. This is the same  *
      * pattern as CCSDS SDLS and PKCS#11 key wrapping.              *
      *                                                                *
      * The public key token (WS-PUB-KEY-TOKEN) is what a CRQC uses  *
      * as input to factor n and recover d.                           *
      *----------------------------------------------------------------*
       WRAP-SESSION-KEY.
           MOVE 16 TO WS-PKA-ENC-LEN

           *    CSNDPKE - PKA Encrypt
           *    Encrypts WS-CLRKEY-DATA (e.g. AES-256 session key)
           *    with the RSA public key using OAEP padding
           CALL 'CSNDPKE' USING
               WS-RETURN-CODE
               WS-REASON-CODE
               WS-EXIT-DATA-LEN
               WS-EXIT-DATA
               WS-PKA-ENC-LEN
               WS-PKA-ENC-DATA        *> 'PKCS-OAEP'
               WS-CLRKEY-LEN          *> 32 = AES-256 key
               WS-CLRKEY-DATA         *> cleartext AES-256 key
               WS-PUB-KEY-TOKEN-LEN
               WS-PUB-KEY-TOKEN       *> RSA-2048 public key token
               WS-CIPHER-LEN          *> 256 bytes (RSA-2048 ciphertext)
               WS-CIPHER-DATA         *> output: RSA-encrypted key

           IF WS-RETURN-CODE NOT = ZERO
               DISPLAY 'CSNDPKE FAILED RC=' WS-RETURN-CODE
               STOP RUN
           END-IF.

       STOP RUN.
