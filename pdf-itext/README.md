# iText / PDFBox — RSA PDF Digital Signatures

**Source:** https://github.com/itext/itext7 (AGPL), https://github.com/apache/pdfbox (Apache-2.0)  
**Reference:** iText Digital Signatures for PDF whitepaper  
**License:** AGPL-3.0 (iText) / Apache-2.0 (PDFBox)

## what it does

iText and Apache PDFBox are the two most widely used libraries for PDF digital signatures in Java. They power government portals, enterprise document workflows, legal systems, and e-signature platforms across hundreds of countries. `sha256WithRSAEncryption` (OID 1.2.840.113549.1.1.11) is the overwhelmingly dominant algorithm in production PDF signatures.

## impact

PDF digital signatures have legal standing under eIDAS (EU), the ESIGN Act (US), and equivalent laws in 50+ countries. a forged RSA signature on a PDF is legally indistinguishable from a real one.

- contracts, court filings, wills, tax documents, medical records, property deeds: all signed with RSA. a CRQC retroactively forges any of them
- Long-Term Validation embeds timestamp tokens and OCSP responses into the PDF. RSA is used throughout that chain too. the entire provenance record is undermined
- PDF spec has allowed RSA since version 1.3 in 1996. decades of documents exist with RSA signatures, and they're all permanently archivable in compromised form
- no PDF reader outside of research labs validates ML-DSA signatures. iText and Adobe exchanged the first ML-DSA PDF as a research milestone in May 2025. not exactly production
## migration status

iText 9.5 (2025) added experimental ML-DSA. PDF Association and Adobe agreed to formalize PQC in the PDF 2.0 spec. No CA issues PQC signing certificates yet. No client validates them in production.
