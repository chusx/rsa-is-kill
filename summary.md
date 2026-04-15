# RSA-is-kill: deep research summary

**Threat model.** Assume a polynomial-time *classical* integer-factoring algorithm is published tomorrow. RSA dies. ECDSA/Ed25519/ECDH (discrete-log on elliptic curves) remain intact. Symmetric primitives (AES, SHA-2/3, HMAC) unaffected. This is **not** Shor's / CRQC — no quantum hardware required, breakage is instantaneous and universally reproducible by any attacker with the public key.

**Corollary.** Any system whose security reduces to RSA signature verification, RSA key-transport (TLS_RSA_*), or RSA-based key wrapping fails. Systems that negotiate ECDHE + authenticate with RSA certs lose *authentication* (MitM) but retain *forward secrecy* for past sessions. Systems that did RSA key-transport (legacy TLS, S/MIME encryption, PGP RSA, CMS key-wrap) lose *all past ciphertext* — harvest-now-decrypt-now.

**Scoring rubric (1–5, 5 = worst).**
- **Criticality** — how load-bearing the RSA trust anchor is for the system's safety/correctness/revenue.
- **Exploitability** — how easily an attacker obtains the needed public key (published? in LDAP? in DNS? in firmware blob? deeply embedded?).
- **BlastRadius** — population/value affected per successful key compromise.
- **Stealth** — how invisible a successful forgery/MitM is to existing detection.
- **Recoverability** — inverse of time-to-remediate; 5 = decade-plus, 1 = hours/days. (Note: inverted from raw — higher = worse = slower recovery.)

**Method.** 150 domain-specific examples were catalogued in prior phases with real-world context (regulator, vendor, standard) and illustrative integration code. This document is the deep-research pass: each entry distills red-team attack path, blue-team recovery plausibility, and four impact dimensions ($, lives, environment, geopolitical), then scores on the rubric above. An aggregate ranking table and top-N prose analysis follow.

---

## Per-example analysis

### acme-lets-encrypt
**Context**: Let's Encrypt has issued 2B+ certs and serves ~60% of HTTPS traffic; ACME (RFC 8555) account keys are RS256 RSA-2048 by Certbot pre-2021 default and almost never rotated. Account keys are long-lived (years), unlike the 90-day certificates.
**Red team (attack)**: Recover RSA-2048 account key from JWK (file or recorded ACME request), then revoke or reissue certs for every domain on that account; for CDN/SaaS shared-account deployments, this is mass cert control. Stealth is high — looks like a legitimate API call from the registered account.
**Blue team (defense/recovery)**: Detection via ACME audit logs and unexpected cert issuance/revocation events, but recovery requires manual `certbot update_account` rotation across millions of deployments. Blocker: no ML-DSA JWS algorithm ID is registered in RFC 8555.
**Impact**:
- $: Tens of billions in HTTPS-dependent commerce disruption
- Lives: Indirect (e-health, telemedicine cert outages)
- Environment: None direct
- Geopolitical: Web PKI controlled mostly by US-based CAs; mass revocation = global outage
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=2. Account keys are publicly-derivable from JWS and gate the majority of the public web.

### nss-firefox
**Context**: NSS underpins ~1.5B Firefox installs, Thunderbird S/MIME, and the entire RHEL/Fedora system crypto stack (yum/dnf/curl/subscription-manager). RSA-2048/4096 still gates TLS cert auth; ML-KEM was added experimentally in 2024 but no ML-DSA.
**Red team (attack)**: Forge any cert chaining to an RSA root in NSS's trust store and Firefox/RHEL tools show a green padlock with no warning, enabling silent HTTPS MitM and malicious package delivery to every RHEL host. Attribution is essentially impossible since the cert validates cryptographically.
**Blue team (defense/recovery)**: CT log monitoring catches new forged certs, but pre-existing RSA roots cannot be removed without breaking the web; trust store rotation is a multi-year coordinated effort with Mozilla, Red Hat, and downstream distros.
**Impact**:
- $: Hundreds of billions (RHEL runs banks, telcos, governments)
- Lives: Healthcare/EHR on RHEL exposed
- Environment: Indirect via SCADA-on-RHEL
- Geopolitical: Mozilla/Red Hat are US entities; non-US sovereignty over CAs collapses
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=2. Trust store is the universal MitM key.

### openssh-host-keys
**Context**: SSH host keys are the server-identity primitive on essentially every Linux/Unix server, router, and embedded device on the internet; RSA-2048/3072 host keys remain the most common type. Shodan/Censys have been archiving every public host key for over a decade.
**Red team (attack)**: Factor any harvested RSA host key, then transparently impersonate that server to any client whose `known_hosts` has cached it — no warning is shown. CI/CD git-push MitM allows silent supply-chain code injection.
**Blue team (defense/recovery)**: Detection requires out-of-band key fingerprint comparison; recovery means rotating host keys on every server and pushing updates to every `known_hosts` file globally. Network gear needs firmware updates that vendors release on multi-year cycles.
**Impact**:
- $: Tens of billions (cloud ops, CI/CD, supply chain)
- Lives: ICS/SCADA SSH access exposes safety systems
- Environment: SSH-managed industrial control = physical risk
- Geopolitical: National telecom routers fall under MitM
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=2. The harvest is already done — Shodan has decades of host keys.

### rpki-routinator
**Context**: RPKI is the cryptographic backbone of BGP route-origin validation; Routinator (NLnetLabs) is the most-deployed validator at major ISPs and IXPs. All RIR trust anchors and ROAs are RSA.
**Red team (attack)**: Forge ROAs for arbitrary prefixes (8.8.8.8/24, root DNS, financial nets) and ISPs doing ROV will actively prefer the cryptographically "valid" hijacked route. Forging an RIR trust anchor rewrites entire regional routing tables.
**Blue team (defense/recovery)**: Detection via BGP anomaly monitoring (RIPE RIS, BGPmon) but the forged routes look authenticated; recovery requires RIRs to reissue trust anchors with non-RSA keys, then every validator rebuilds its trust store.
**Impact**:
- $: Hundreds of billions (global routing disruption, payment networks)
- Lives: Emergency comms, 911 routing, hospital VPNs
- Environment: None direct
- Geopolitical: A nation-state can reroute another state's traffic through its own ASes — pure sovereignty kill
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=4, Recoverability=2. RPKI inverts safely-failed BGP into authenticated attack.

### dnssec-bind9
**Context**: BIND9 is the most-deployed authoritative/recursive DNS server; the DNS root KSK is RSA-2048 and signs the entire DNS hierarchy. RSA-1024 ZSKs still exist in thousands of zones.
**Red team (attack)**: Forge the root KSK or any TLD KSK and every DNSSEC-validated response on the internet becomes forgeable, redirecting any name to attacker-controlled IPs; DANE pinning collapses with it. Stealth is high since responses validate cleanly.
**Blue team (defense/recovery)**: Detection via passive DNS comparison (Farsight, Cisco Umbrella) but root KSK rollover is a multi-year ICANN ceremony — last one took ~3 years from announcement to completion.
**Impact**:
- $: Trillions if root forged (entire internet name resolution)
- Lives: Emergency services rely on DNS
- Environment: ICS that resolves cloud telemetry endpoints
- Geopolitical: ICANN/IANA are US-rooted; root KSK forgery = US-jurisdictional attack on global namespace
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=4, Recoverability=1. Root KSK rollover is the slowest crypto migration in the world.

### opendkim
**Context**: OpenDKIM is the dominant DKIM implementation; nearly every outbound mail server signs with RSA-1024 or RSA-2048 keys whose public halves are published in DNS. DMARC and BIMI both ride on DKIM.
**Red team (attack)**: Pull any domain's DKIM public key from DNS, factor, and forge perfectly authenticated email from president@whitehouse.gov, ceo@bigbank.com, etc. — passing DMARC/BIMI with verified-brand logos. Indistinguishable from real mail at every check.
**Blue team (defense/recovery)**: Detection requires content/behavioral filtering since cryptographic checks pass; recovery means rotating every DKIM selector to non-RSA — but no IETF-blessed PQ DKIM exists yet.
**Impact**:
- $: Tens of billions in BEC/wire fraud annually amplified
- Lives: Spear-phishing of healthcare/military staff
- Environment: None
- Geopolitical: Forged diplomatic/embassy mail at scale
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=5, Recoverability=3. Public keys in DNS are an open invitation.

### postfix-smtp-tls
**Context**: Postfix is the dominant MTA across ISPs, universities, and government; default smtpd_tls_cert_file is RSA-2048 generated at install. STARTTLS on port 25 hands the public key to anyone who connects.
**Red team (attack)**: Harvest any MTA's RSA cert from port 25, factor, then MitM SMTP-in-transit between mail servers — bypassing MTA-STS/DANE because you hold the legitimate-looking key. Intercept password resets, MFA codes, and wire-transfer confirmations in flight.
**Blue team (defense/recovery)**: Detection via certificate pinning monitors and TLS fingerprint anomalies, but opportunistic STARTTLS already has a low security baseline. Recovery requires coordinated migration across Postfix/Exim/Exchange/Gmail.
**Impact**:
- $: Tens of billions (BEC, wire-fraud reset interception)
- Lives: MFA codes for medical/critical-infra logins
- Environment: None
- Geopolitical: .gov/.mil MX hosts publicly scannable
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=3. Public keys literally served by every mail server on port 25.

### smime-email
**Context**: S/MIME (RFC 8551) is the legally-binding email signing/encryption standard for US DoD CAC, EU eIDAS QES, HIPAA, German BSI DE-Mail, and bank/legal communications, all on RSA-2048/4096. Encryption is persistent — the same RSA key wraps years of archived messages.
**Red team (attack)**: Factor any individual's public S/MIME cert (in headers, LDAP, CAC databases) and retroactively decrypt every encrypted email ever sent to them, plus forge legally-binding signatures going forward. Pure HNDL play against archived corporate/government inboxes.
**Blue team (defense/recovery)**: Almost no live detection — decryption is offline; recovery requires LAMPS WG to finalize PQ-CMS drafts, every client (Outlook, Apple Mail) to update, and CAs to reissue. Multi-year minimum.
**Impact**:
- $: Tens of billions (M&A, legal privilege, IP exfil)
- Lives: HIPAA/EHR records exposed, including psychiatric/HIV data
- Environment: None direct
- Geopolitical: DoD CUI, German federal mail, EU legal proceedings retroactively readable
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=4, Stealth=5, Recoverability=1. Persistent encryption + archived ciphertext = perfect HNDL target.

### cyrus-imap
**Context**: Cyrus IMAP is the mailbox backend for CMU, Fastmail (historically), most universities, Kolab Groupware, and BSI-blessed German federal/Bundeswehr/Swiss federal email. TLS server cert is RSA-2048 via OpenSSL.
**Red team (attack)**: Factor the IMAP server cert (TLS handshake scan), then MitM IMAPS to read inbound mailbox fetches, sync_client replication, and SASL EXTERNAL-authenticated client cert sessions — including ministerial mail. Indistinguishable from the real server.
**Blue team (defense/recovery)**: Detection via TLS fingerprint pinning and SPKI monitoring; recovery is per-deployment cert reissue once OpenSSL/Cyrus support PQ — no Kolab roadmap, no BSI mandate yet.
**Impact**:
- $: Single-digit billions (regional/sectoral)
- Lives: Government continuity, defense correspondence
- Environment: None
- Geopolitical: German/Swiss federal email reading by external actors = sovereignty breach
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=3, Stealth=4, Recoverability=3. Smaller blast radius than Postfix but higher per-target sensitivity.

### openldap-tls
**Context**: OpenLDAP slapd is the directory backbone for most Linux enterprise identity (SSSD, K8s dex, replication topologies); SASL EXTERNAL means the RSA-2048 client cert IS the credential. Server and replica certs all RSA via OpenSSL.
**Red team (attack)**: Forge a TLS client cert with `cn=Directory Manager` DN, slapd auto-maps to LDAP superuser — full read/write of every credential and group membership. Forged replica certs let you inject entries that propagate to every consumer.
**Blue team (defense/recovery)**: Detection via slapd audit logs catching unexpected DN binds; recovery requires CA rotation and reprovisioning every issued client cert — typical ADCS-driven enterprise lacks PQ issuance entirely.
**Impact**:
- $: Tens of billions (Linux enterprise IAM compromise)
- Lives: Indirect via downstream healthcare/critical infra IAM
- Environment: SCADA/OT often LDAP-bound for ops accounts
- Geopolitical: Sovereign Linux fleets (gov, defense) lose IAM
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=2. Cert IS the credential — forgery is total identity theft.

### kerberos-pkinit
**Context**: PKINIT (RFC 4556) is how smartcards, Windows Hello for Business, and DC-to-DC auth log into Kerberos/Active Directory; client/KDC/CA certs are all RSA and stored in the AD `userCertificate` attribute readable by any domain user.
**Red team (attack)**: Pull any user's RSA cert from LDAP, forge the PKINIT signature, get a TGT for any account including Domain Admins — bypassing smartcard, password, and MFA. Indistinguishable from a normal smartcard logon in DC logs.
**Blue team (defense/recovery)**: Detection via anomalous TGT-issuance patterns (non-smartcard hours, geographic mismatches); recovery has no path — no PQ PKINIT RFC, no Microsoft KDC PQ validation, no timeline.
**Impact**:
- $: Hundreds of billions (full enterprise AD compromise across F500)
- Lives: AD-protected hospital/utility/defense systems
- Environment: OT environments AD-joined for management
- Geopolitical: AD is the identity layer for most western defense, financial, and government IT
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=1. The input is in LDAP; the output is domain admin.

### saml-ruby
**Context**: ruby-saml powers SAML 2.0 SSO across Okta, Azure AD, GitHub, GitLab, Salesforce, and most Ruby enterprise apps. XMLDSig spec defines four signature algorithms — all RSA — with RSA-SHA1 as ruby-saml default.
**Red team (attack)**: Pull the IdP signing cert from public SAML metadata XML, factor, and forge SAML assertions for any user (including admins/execs) at every SP that trusts that IdP — no MFA, password, or session checked. Single key often covers entire organization.
**Blue team (defense/recovery)**: Detection via SP-side anomaly detection on assertion-issuance velocity/geo; recovery requires W3C XMLDSig spec update for non-RSA URI plus IdP/SP coordination across billions of daily assertions.
**Impact**:
- $: Tens of billions (SaaS data exfil, financial-app impersonation)
- Lives: Healthcare SSO, EHR access
- Environment: None
- Geopolitical: Cloud SSO is mostly US-vendor; nation-state SSO impersonation enables broad espionage
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=2. Metadata XML hands attackers the input.

### jwt-libjwt
**Context**: RS256 JWTs are the default for OAuth2, OIDC, Kubernetes ServiceAccounts, AWS Cognito, Azure AD, GCP Identity, Okta, Auth0; the public verification key is published openly at the `jwks_uri`. PS256 (RSA-PSS) also breaks.
**Red team (attack)**: Fetch `jwks_uri`, factor, mint JWTs with arbitrary claims (`cluster-admin`, `billing:write`, root scopes) — every API gateway accepts them. Long-lived service-to-service tokens enable infinite replay.
**Blue team (defense/recovery)**: Detection via token-issuance anomalies, token binding, or DPoP; recovery requires IANA JOSE algorithm IDs for ML-DSA, every IdP rotating JWKS, every client library updating.
**Impact**:
- $: Hundreds of billions (cloud-resource theft, K8s cluster compromise)
- Lives: K8s-hosted healthcare workloads
- Environment: K8s-managed industrial telemetry
- Geopolitical: US hyperscalers run global K8s; sovereignty over forged-token blast radius is none
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=2. The verification key is published by design.

### samba-netlogon
**Context**: Samba AD DCs replace Windows Server for tens of thousands of mixed Linux/Windows AD environments; `samba-tool domain provision` hardcodes RSA-2048 for the domain CA, KDC PKINIT, LDAP TLS, and SMB3-over-QUIC TLS. Heimdal hx509 + GnuTLS, neither PQ-ready.
**Red team (attack)**: Read the Samba CA cert from LDAP (`CN=Configuration`, any-user-readable), factor, issue arbitrary user/computer certs and PKINIT to TGT-as-Domain-Admin. SMB3-TLS MitM exfiltrates files and harvests NTLM if mixed mode.
**Blue team (defense/recovery)**: Detection via KDC ticket-issuance anomalies; recovery requires reprovisioning the domain (a bone-shattering operation in production AD) once Heimdal/GnuTLS ship PQ.
**Impact**:
- $: Single-digit billions (smaller install base than Windows AD)
- Lives: Manufacturing/SMB hospital deployments
- Environment: Linux file servers in OT
- Geopolitical: Open-source AD is favored by sovereign-Linux nations (Germany, Brazil, India)
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=5, Recoverability=2. CA cert is world-readable; reprovisioning is brutal.

### sap-netweaver-sso
**Context**: SAP NetWeaver runs ERP/HR/finance for ~77% of global transaction revenue; SAP Logon Tickets (MYSAPSSO2), X.509 client cert SSO, HANA TLS, and Web Dispatcher all use RSA-2048 via SAP CommonCryptoLib (OpenSSL-wrapped). Issuer public cert sits in STRUST and is widely distributed to integration partners.
**Red team (attack)**: Factor the issuer's RSA-2048 from STRUST/PEM export, forge MYSAPSSO2 tickets as SAP_BASIS, then alter GL entries, vendor bank accounts, and approval signatures at the database layer; HANA-MitM rewrites query results inside the trusted segment.
**Blue team (defense/recovery)**: Detection via SAP Enterprise Threat Detection for anomalous SAP_BASIS activity; recovery requires SAP to ship PQ in CommonCryptoLib + STRUST + ticket format simultaneously across multi-system landscapes — a multi-year vendor-coordinated migration.
**Impact**:
- $: Trillions (financial-close integrity for the Fortune 500)
- Lives: Pharma/medical-device SAP MES, payroll for healthcare workers
- Environment: SAP MES controls plant operations, hazardous-material logistics
- Geopolitical: German Bundesverwaltung, DoD contracts, every G20 ministry runs SAP
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=1. Forging GL entries and approvals is financial-system-of-record collapse.

