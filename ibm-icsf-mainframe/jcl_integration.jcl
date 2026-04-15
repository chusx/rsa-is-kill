//ICSFRSA  JOB (ACCT),'RSA SIGN VERIFY',CLASS=A,MSGCLASS=X,
//             NOTIFY=&SYSUID,REGION=0M
//*
//* Production JCL wrapper around the ICSF RSA COBOL caller
//* (`icsf_rsa_cobol.cbl`).  Runs on z/OS 2.5 / 3.1 LPARs across
//* every major bank, insurer, airline GDS (SABRE/Galileo), retailer
//* credit authorization host, and public-sector mainframe shop
//* (SSA, IRS, CMS, HMRC, state DMVs).
//*
//* The ICSF address space (CSF) fronts the CCA / PKCS#11 engines
//* inside the CryptoExpress8S (or older CEX7S/CEX6S) PCIe coprocessor,
//* where the RSA private keys live inside CCA TKE-managed master-key
//* wrapped token stores (CKDS/PKDS).
//*
//STEP01   EXEC PGM=ICSFSIGN,PARM='MODE=SIGN'
//STEPLIB  DD   DISP=SHR,DSN=SYS1.SIEALNKE
//SYSPRINT DD   SYSOUT=*
//*
//* CKDS / PKDS — master-key-wrapped symmetric and RSA private key
//* datasets. TKE workstation quorum (M-of-N) is required to load
//* master keys; PKDS RSA records never leave the HSM in the clear.
//*
//CSFCKDS  DD   DISP=SHR,DSN=SYS1.CSF.CKDS
//CSFPKDS  DD   DISP=SHR,DSN=SYS1.CSF.PKDS
//*
//* Payload to sign — an ACH Nacha batch, an EMV issuer authorization
//* response, a SWIFT MT message, or a PKCS#10 CSR awaiting the
//* enterprise RSA Issuing CA (CCA PKA token type "PKDSIGN").
//*
//INPUT    DD   DISP=SHR,DSN=BANKOPS.ACH.BATCH.D&YYMMDD..OUT
//SIGOUT   DD   DSN=BANKOPS.ACH.BATCH.D&YYMMDD..SIG,
//              DISP=(NEW,CATLG,DELETE),SPACE=(TRK,(5,5)),
//              DCB=(RECFM=FB,LRECL=256,BLKSIZE=27648)
//*
//* RACF check: the job must be permitted to CSFDSV / CSFDSG on
//* SAF class CSFSERV and READ on CSFKEYS for label
//* "BANK.ACH.SIGNKEY.2026".  Without this, ICSF refuses the call.
//*
//SYSIN    DD   *
 RSA_KEY_LABEL     = 'BANK.ACH.SIGNKEY.2026'
 RSA_MODULUS_BITS  = 4096
 RSA_ALGORITHM     = 'PSS-SHA256'
 INPUT_DD          = 'INPUT'
 OUTPUT_DD         = 'SIGOUT'
 AUDIT_CATEGORY    = 'ACH-RELEASE'
/*
//*
//STEP02   EXEC PGM=FTP,COND=(0,NE,STEP01)
//SYSPRINT DD   SYSOUT=*
//INPUT    DD   *
 ach-gateway.fedwire.example.com
 BANKOPS
 /password:via:PassTicket
 binary
 send 'BANKOPS.ACH.BATCH.D&YYMMDD..SIG'
 send 'BANKOPS.ACH.BATCH.D&YYMMDD..OUT'
 quit
/*
//*
//* Reality: the ICSF RSA signing path is what releases billions of
//* dollars of wire/ACH batches, card auth responses, and treasury
//* transactions per day on each major bank's z/OS.  An RSA factoring
//* attack against the master-key-wrapped RSA private token is a
//* different threat — the wrapped token isn't useful standalone —
//* BUT factoring the *public* modulus lets an attacker forge
//* signatures that downstream partners accept, bypassing the HSM
//* entirely. Correspondent banks receiving the signed batch have
//* only the RSA pubkey and a trust-anchor; they don't see that the
//* signature came from a forgery instead of the CEX8S. This is a
//* core argument for why banks are the first industry to demand
//* post-quantum-capable coprocessors in their mainframe fleet.
