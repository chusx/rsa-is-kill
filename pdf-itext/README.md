# iText / PDFBox — RSA PDF Digital Signatures

**Source:** https://github.com/itext/itext7 (AGPL), https://github.com/apache/pdfbox (Apache-2.0)  
**Reference:** iText Digital Signatures for PDF whitepaper  
**License:** AGPL-3.0 (iText) / Apache-2.0 (PDFBox)

## what it does

iText and Apache PDFBox are the two most widely used libraries for PDF digital signatures in Java. They power government portals, enterprise document workflows, legal systems, and e-signature platforms across hundreds of countries. `sha256WithRSAEncryption` (OID 1.2.840.113549.1.1.11) is the overwhelmingly dominant algorithm in production PDF signatures.

## why it matters legally and practically

- PDF digital signatures have **legal standing** under eIDAS (EU), ESIGN Act (US), and equivalent laws in 50+ countries. A forged RSA signature on a PDF is legally indistinguishable from a real one.
- Contracts, court documents, wills, tax filings, medical records, property deeds — all signed with RSA. A CRQC retroactively forges any of them.
- PDF spec allows RSA since version 1.3 (1996). Decades of documents exist with RSA signatures.
- No PDF reader outside research labs validates ML-DSA signatures. The first ML-DSA PDF was exchanged between iText and Adobe in May 2025 — as a research milestone, not production use.
- The entire eIDAS trust infrastructure (EU Trust Lists, Qualified CAs) is RSA/ECDSA.

## migration status

iText 9.5 (2025) added experimental ML-DSA. PDF Association and Adobe agreed to formalize PQC in the PDF 2.0 spec. No CA issues PQC signing certificates yet. No client validates them in production.
