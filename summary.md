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

### fido2-webauthn
**Context**: FIDO2/WebAuthn authenticators (YubiKey 5, Google Titan, Windows Hello, platform TPMs) ship attestation roots in RSA-2048/3072; billions of user accounts rely on it as phishing-resistant MFA and in many deployments as passwordless primary credential. RP policy often requires attestation-chain validation to the vendor root.
**Red team (attack)**: Factor Yubico/Feitian/Google attestation roots, mint software "authenticators" that attest as genuine hardware; bypass enterprise attestation policies (DoD CAC-alt, GitHub enterprise, Azure AD phishing-resistant tiers) and enroll into any account allowing self-registration. Per-credential keys are ECDSA/Ed25519 in modern authenticators so already-enrolled creds survive — the break is enrollment trust.
**Blue team (defense/recovery)**: Vendors can ship new attestation roots via firmware, but RP trust stores must update out-of-band; most RPs don't actually pin roots strictly so detection is weak. Recovery is fast for the vendors, slow for the RP ecosystem.
**Impact**:
- $: Hundreds of billions (account-takeover exposure at every MFA-protected service)
- Lives: Healthcare/ICS operator accounts protected by WebAuthn
- Environment: Indirect (access to OT portals)
- Geopolitical: US/EU vendor dominance; CN/RU would gain parity via forgery
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3. Strict attestation is rare; most RPs fail open.

### piv-cac-smartcard
**Context**: US DoD CAC (~3.5M active) and federal PIV (~5M) are RSA-2048 smartcards under FIPS 201 / NIST SP 800-73; they sign Windows smartcard-logon, S/MIME federal email, and PKI-authenticated access to SIPRNet-adjacent systems. DoD PKI roots are RSA-2048/3072 and widely trusted.
**Red team (attack)**: Factor DoD Root CA 3/6/PIV roots; issue card-equivalent certs out of software, log into every PIV-gated portal (DTS, milSuite, contractor portals) as any cleared identity, sign S/MIME as flag officers. Lateral into SIPRNet-bridged systems via cross-cert trust.
**Blue team (defense/recovery)**: DoD would revoke via CRL/OCSP and ship new roots, but re-issuing 8.5M cards takes years; interim forces fallback to CAC+password+bio with degraded assurance. Fort Meade owns the recovery runbook; it's painful but rehearsed.
**Impact**:
- $: Tens of billions (contractor productivity collapse + re-issuance)
- Lives: Mil-medical, clearance-gated safety systems
- Environment: Minimal direct
- Geopolitical: Nation-state-adversary wet dream: full federated-identity impersonation across USG
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=2. Re-issuing 8.5M cards is a years-long logistics project.

### gnupg-openpgp-card
**Context**: OpenPGP smartcards (Yubikey OpenPGP applet, Nitrokey, ZeitControl OpenPGP v3) hold RSA-2048/4096 keys used by Debian/kernel maintainers, Linux distro signers, and privacy activists; Werner Koch's GnuPG is still RSA-default in many deployments.
**Red team (attack)**: Factor any maintainer's published RSA pubkey from keyservers, sign malicious kernel commits, upload malicious Debian packages (dpkg-sig) or tarballs. Key transparency for PGP is nil.
**Blue team (defense/recovery)**: Push kernel.org and Debian to Ed25519/Curve448 (already supported); revoke old keys via WoT. But years of historic signed artifacts become unverifiable retroactively.
**Impact**:
- $: Billions (Linux distro supply-chain)
- Lives: Indirect (kernel in medical/auto)
- Environment: None direct
- Geopolitical: Dissident communications (journalists, activists) deanonymized via forged signatures
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=3. ECC-PGP migration is already partly done; distros can move fast.

### gnupg
**Context**: GnuPG is the Swiss-army PGP implementation baked into apt, rpm, git tag signing, release tarballs for ~every open-source project. Default keys generated 2010-2020 are predominantly RSA-2048/3072.
**Red team (attack)**: Factor the release-signing keys of high-value projects (Linux kernel, curl, OpenSSL, systemd), forge signed tarballs; compromise every distro that validates upstream tags. Same break feeds rpm-gpg and apt attacks.
**Blue team (defense/recovery)**: Ed25519 migration for master keys; distros need to re-sign historic releases with PQ keys and publish new keyrings. GnuPG maintainers (tiny team) would be overwhelmed.
**Impact**:
- $: Tens of billions (OSS supply-chain)
- Lives: Downstream medical/auto/ICS code
- Environment: None direct
- Geopolitical: Universal impact; OSS is global commons
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=3. Ed25519 path exists but historical artifacts are unsalvageable.

### pkcs11-softhsm
**Context**: PKCS#11 is the HSM API every enterprise CA, code-signing service, and TLS-termination stack plugs into; SoftHSM2 and Thales/Entrust/AWS CloudHSM expose RSA-2048/3072/4096 keys. Billions of enterprise signing ops/day flow through PKCS#11.
**Red team (attack)**: Many keys are never rotated (10+ year CA keys); factoring extracts the equivalent of an HSM export. Red team targets the *published* public keys from CT logs / cert distributions — the HSM's "non-extractable" property is defeated.
**Blue team (defense/recovery)**: HSM vendors already support ML-DSA in newer FW revs; enterprises must rotate every RSA key. Years of work per Fortune 500.
**Impact**:
- $: Hundreds of billions
- Lives: ICS/medical signing keys rotate through PKCS#11
- Environment: Indirect
- Geopolitical: Thales/Entrust are FR/US; sovereign HSM (Utimaco-DE, Crypto4A-CA, Atos-FR) would gain procurement leverage
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=2. "Non-extractable" means nothing when math is the exfil channel.

### authenticode-pe
**Context**: Microsoft Authenticode signs Windows PE binaries, drivers, MSI installers; RSA-2048/3072 via CAs cross-signed to Microsoft Root. Drivers require Microsoft countersignature (WHQL). Every Windows install (~1.5B) trusts this chain for driver loading and SmartScreen reputation.
**Red team (attack)**: Factor Microsoft Code Signing PCA or WHQL-holder vendor keys (many published in CT-adjacent transparency or in leaked vendor PFX files), sign malicious kernel drivers that load on every Windows box including Secure-Boot-enforced S Mode. Rootkit-grade persistence, globally, silently.
**Blue team (defense/recovery)**: Microsoft distributes revocation via AM signatures, deprecates the root; but historic signed binaries clutter CRLs. Driver ecosystem rebuild is painful. MS has PQ roadmap via SymCrypt.
**Impact**:
- $: Hundreds of billions (incident response at scale of CrowdStrike×10)
- Lives: Windows runs on ICS workstations, hospital front-ends, military desktops
- Environment: Indirect via ICS Windows hosts
- Geopolitical: US-vendor lock-in on global endpoint integrity
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=2. Kernel-driver code-signing failure is the single worst desktop outcome.

### rpm-gpg-signing
**Context**: RHEL/Fedora/SUSE/Amazon Linux package signing uses RPM+GPG with RSA-2048/4096; `dnf` refuses unsigned packages by default. Signs all updates for Fedora/RHEL (~millions of hosts including every major bank, ICS vendor and Big Tech Linux fleet).
**Red team (attack)**: Factor Red Hat / CentOS / Amazon Linux release keys (all public on keyservers), publish malicious packages to any mirror, catch millions of `dnf update` runs. CI/CD immutable-image pipelines re-poison on rebuild.
**Blue team (defense/recovery)**: Distros rotate to Ed25519/ML-DSA, re-sign repos, ship new keyrings via out-of-band channel. But repos have 20+ years of history; downstream mirrors are slow.
**Impact**:
- $: Tens of billions
- Lives: RHEL in hospital backends, ICS historians
- Environment: None direct
- Geopolitical: IBM-RH is US; sovereign Linux distros (Kylin-CN, Astra-RU) would gain leverage
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=3.

### debian-apt-signing
**Context**: Debian/Ubuntu InRelease + Release.gpg under RSA-4096 for archive keys; Canonical's Ubuntu-archive-automatic-signing-key signs updates consumed by 40%+ of cloud VMs globally. Apt-transport-https is signature-based, not TLS-trust-based.
**Red team (attack)**: Factor Ubuntu archive key (public on keyserver.ubuntu.com), run a malicious mirror, inject backdoored openssh-server on next apt-get upgrade across AWS/Azure/GCP. Harvest SSH host keys and move laterally.
**Blue team (defense/recovery)**: Canonical has ML-DSA plans; rebuild archive signing infra, ship new key via apt-key rotation and out-of-band channels (cloud-init baked images). Debian tech-ctte bottleneck; months minimum.
**Impact**:
- $: Tens of billions (cloud-wide)
- Lives: Ubuntu on clinical decision-support, manufacturing
- Environment: None direct
- Geopolitical: UK-based Canonical; sovereignty angle moderate
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=3.

### openjdk-jarsigner
**Context**: Signed JAR/APK (Android v1 scheme) + Java applet + Java Web Start + enterprise Java EE EAR signing under RSA-2048/3072; trust anchored in JRE `cacerts` (shared with OS or bundled). Every Oracle/OpenJDK install and ~half of enterprise middleware.
**Red team (attack)**: Factor CA roots in `cacerts` (same roots as browsers + a few Oracle-specific); forge signed JARs to sideload into privileged Java containers (WebLogic, JBoss), tamper with signed-code permission grants. Factor Android v1-scheme signer keys to backdoor pre-Android-7 firmware OTAs still in circulation.
**Blue team (defense/recovery)**: Oracle ships PQ in JDK 24+; ecosystem migration is the bottleneck. APK v1 is legacy but present.
**Impact**:
- $: Tens of billions (enterprise Java)
- Lives: Java in hospital systems, tax systems
- Environment: None direct
- Geopolitical: Oracle-US; India/China run Java-heavy stacks
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3.

### shim-uefi
**Context**: shim.efi is the Red Hat-maintained UEFI first-stage that Microsoft signs so Linux distros can Secure-Boot on consumer hardware; shim then verifies the distro-signed GRUB/kernel with RSA-2048 embedded keys. Every Secure-Boot Linux laptop + ~every Linux cloud VM with SB on.
**Red team (attack)**: Factor distro shim keys (RH, Canonical, Debian, SUSE, Oracle) or the Microsoft 3rd Party UEFI CA itself; ship malicious bootloader that survives OS reinstall and runs before the kernel sees it. Bootkitting at scale; BlackLotus-class generalized.
**Blue team (defense/recovery)**: UEFI dbx revocation updates, new shim builds signed by a new MS CA; motherboard firmware updates required. Historically slow (years to propagate dbx).
**Impact**:
- $: Tens of billions
- Lives: Pre-boot persistence on medical/ICS Linux hosts
- Environment: Indirect
- Geopolitical: Microsoft as UEFI root-of-trust is a single-vendor chokepoint
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=2. Boot-level persistence is the worst endpoint outcome.

### android-avb
**Context**: Android Verified Boot 2.0 verifies boot/vendor/system partitions with RSA-2048/4096 vbmeta signatures; each OEM (Samsung, Xiaomi, Pixel, OPPO) embeds their public key in the tamper-evident boot ROM or hardware root-of-trust. 3B+ devices.
**Red team (attack)**: Factor OEM AVB keys (exposed via teardown dumps or public fastboot tools), sign malicious boot/vbmeta images, flash via unlocked or supply-chain-compromised fastboot to bypass rollback and inject persistent bootkits. Pixel's key is Google-held with better hygiene than Tier-2 OEMs.
**Blue team (defense/recovery)**: OTA-push new vbmeta with rollback index bumps; ROM-fused keys cannot be rotated — bricked trust for older SoCs. Newer devices (Pixel 8+, Samsung S24+) have ML-DSA-capable silicon paths.
**Impact**:
- $: Tens of billions (device replacement for unrotatable ROM keys)
- Lives: Android runs in healthcare tablets, first-responder gear
- Environment: E-waste tsunami from forced replacement
- Geopolitical: Samsung/Xiaomi/Google device fleets globally; CN domestic AVB forks bypass Google entirely
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=1. ROM-fused keys are un-rotatable; this is the worst mobile outcome.

### uboot-secure-boot
**Context**: U-Boot FIT image verification signs kernels/DTBs with RSA-2048/4096 for ~every embedded Linux device (routers, set-top boxes, industrial gateways, EV chargers, medical edge gear). Keys are per-OEM, baked into SoC OTP or read-only flash.
**Red team (attack)**: Factor OEM U-Boot signing key (often recoverable from published firmware images), sign malicious kernel, deliver via update server MITM or physical access. Embedded device root-of-trust collapse across a product line.
**Blue team (defense/recovery)**: Newer SoCs (NXP i.MX9, STM32MP2) support ML-DSA in ROM; legacy SoCs are done — throw-away replacement. mainline U-Boot added ML-DSA experimentally in 2025.
**Impact**:
- $: Tens of billions (embedded device replacement)
- Lives: Medical edge gateways, EV chargers, IoT gear
- Environment: Gigantic e-waste; EV charging grid reliability
- Geopolitical: Broadcom/NXP/ST/MediaTek key hygiene varies hugely
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=1.

### arm-trustzone-tfa
**Context**: ARM Trusted Firmware-A (TF-A) is the BL1/BL2 bootloader for ~every Cortex-A SoC (phones, servers, auto MCUs); signs BL31/BL32/BL33 with RSA-2048/3072 under a chain-of-trust configured by the SoC vendor. Graviton, Apple M, Snapdragon, Tegra all derive from this pattern.
**Red team (attack)**: Factor SoC-vendor CoT keys, forge BL31 (EL3 secure monitor) images, own every Cortex-A below the OS. TEE (TrustZone) attestation becomes meaningless — DRM, payment, keystore all crumble.
**Blue team (defense/recovery)**: TF-A upstream has ML-DSA in mainline 2.13+; SoC ROMs that hardcode RSA verification are un-upgradable. AWS Graviton fleet would need silicon refresh.
**Impact**:
- $: Hundreds of billions (datacenter + mobile silicon)
- Lives: Auto ECUs, medical devices running Cortex-A
- Environment: Massive silicon refresh footprint
- Geopolitical: ARM-IP is UK/US; RISC-V alternative would accelerate
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=1.

### hsm-firmware-signing
**Context**: Thales, Entrust/nShield, Utimaco, AWS CloudHSM, YubiHSM firmware updates are signed with vendor RSA-4096 roots; installed in banking core, PKI, crypto exchanges, sovereign CAs.
**Red team (attack)**: Factor HSM vendor firmware root; push malicious FW that exfiltrates every tenant's key material ("HSM with a side channel"). Bank PINs, CA root keys, crypto exchange hot wallets — all extractable.
**Blue team (defense/recovery)**: HSM vendors have FIPS 140-3 PQ modules in field validation (2024-2026); customers must re-provision every HSM and re-key every CA. Disaster-grade project.
**Impact**:
- $: Trillions (banking core + exchange custody)
- Lives: ICS signing flows
- Environment: None direct
- Geopolitical: Thales-FR, Entrust-US, Utimaco-DE — concentrated sovereign dependency
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=1. The keystone of the enterprise crypto fabric.

### autosar-ecu-hsm
**Context**: AUTOSAR SecOC + ECU HSM (Secure Hardware Extension / EVITA) sign CAN-FD/FlexRay/Ethernet payloads and authorize ECU firmware updates; RSA-2048 is prevalent in 2015-2024 platforms (Bosch, Continental, Denso, ZF). ~100M vehicles/year.
**Red team (attack)**: Factor OEM (VW, Toyota, Stellantis, GM, Ford) ECU-update signing keys; push malicious calibrations or firmware via dealer tool or OTA, manipulate torque, brake, ADAS. Remote-triggered unsafe behavior at fleet scale.
**Blue team (defense/recovery)**: OEM PQ roadmaps exist (VW MEB, Stellantis STLA Brain target 2027+); field ECU re-flashing is dealer-visit-per-vehicle for 100M+ cars. Many ECUs' ROM keys are un-rotatable.
**Impact**:
- $: Hundreds of billions (recall + warranty)
- Lives: Direct — brake/steering/powertrain manipulation
- Environment: Mass unsafe vehicle behavior
- Geopolitical: OEMs are multinational; China's domestic SH-HSM (GOST + SM2) attractive as alternative
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=1. One of the top mass-casualty scenarios.

### tpm2-rsa-ek
**Context**: TPM 2.0 Endorsement Keys are RSA-2048 certificates from manufacturer CAs (Infineon, Nuvoton, STMicro, Intel PTT, AMD fTPM) used for device attestation across Windows Hello for Business, Intune compliance, Azure AD device identity, and enterprise DRM. ~2B endpoints.
**Red team (attack)**: Factor TPM-vendor EK CA roots; mint software "TPMs" that attest as genuine hardware to Azure AD/Intune/Windows Hello, extract BitLocker keys from fake-sealed blobs, defeat measured-boot-based conditional access. Hardware attestation becomes unverifiable.
**Blue team (defense/recovery)**: TPM 2.0 spec supports ECC-EK; Microsoft can pivot Windows policy to require ECC-EK attestation over RSA. Old silicon is stuck on RSA-EK forever.
**Impact**:
- $: Hundreds of billions (enterprise MDM + DRM posture)
- Lives: ICS/hospital endpoints relying on TPM-sealed creds
- Environment: None direct
- Geopolitical: Infineon-DE, Nuvoton-TW, STMicro-CH/FR — diversified
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=2. Hardware-backed identity collapses.

### intel-sgx-signing
**Context**: Intel SGX enclaves require enclave authors' RSA-3072 key for MRSIGNER; remote attestation (EPID/DCAP) ultimately chains to Intel's RSA attestation roots. Runs confidential-compute workloads at Microsoft (Azure confidential VMs), Signal contact discovery, MobileCoin, and every blockchain "TEE oracle."
**Red team (attack)**: Factor Intel PCK/root attestation keys; forge attestation quotes for arbitrary enclave measurements, break confidential-VM and blockchain-oracle trust models. Signal's private-contact-discovery premise disappears.
**Blue team (defense/recovery)**: Intel ships TDX + new attestation keys with ML-DSA in newer Xeons; SGX is sunset on client anyway. Confidential-compute customers would migrate to AMD SEV-SNP or re-architect.
**Impact**:
- $: Billions (confidential-compute market)
- Lives: None direct
- Environment: None direct
- Geopolitical: Intel-US; AMD SEV-SNP uses ECDSA so it's less exposed
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=5, Recoverability=3.

### intel-tdx-quote
**Context**: Intel TDX Quotes for trust-domain attestation currently use RSA-3072 in the PCK chain; Azure confidential AI, Google Cloud confidential VMs, and DoD IL6 exploratory deployments rely on it.
**Red team (attack)**: Factor Intel PCK chain, forge TDX quotes for fake trust domains; defeat attestation-gated unseal of customer keys in KMS. Same pattern as SGX but in-scope for the modern confidential-AI stack.
**Blue team (defense/recovery)**: Intel has FIPS-204 roadmap for PCK; attestation verifiers (Azure Attestation, ITA) can rotate. Fleet re-provisioning is manageable because TDX is new.
**Impact**:
- $: Tens of billions (confidential AI future market)
- Lives: None direct
- Environment: None direct
- Geopolitical: Confidential-AI sovereignty (EU AI Act, DoD) depends on Intel attestation
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=5, Recoverability=3.

### nvidia-gpu-attestation
**Context**: NVIDIA H100/H200/B200 Confidential Computing attestation uses RSA-3072 device identity cert chains issued by NVIDIA roots; critical to AI-training provider attestation (Azure ND-H100, AWS P5, GCP A3) and sovereign-AI deployments.
**Red team (attack)**: Factor NVIDIA attestation root (published for verifier ecosystem); forge GPU attestations, masquerade software as confidential H100 to siphon model weights or training data from confidential-AI customers. Frontier-lab model theft via fake attestation.
**Blue team (defense/recovery)**: NVIDIA can ship new roots via FW/driver; on-chip un-rotatable keys are the tail risk. Verifier ecosystem (Microsoft MAA, NVIDIA NRAS) can update quickly.
**Impact**:
- $: Tens of billions (frontier-AI IP is the crown jewel)
- Lives: None direct
- Environment: None direct
- Geopolitical: US-NVIDIA dominance; frontier-model exfil to CN/RU is a national-security concern
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=5, Recoverability=3.

### coco-attestation
**Context**: CNCF Confidential Containers (CoCo) uses KBS (Key Broker Service) verifying TEE attestation quotes (SGX/TDX/SEV-SNP/CCA) then unsealing workload keys — predominantly RSA-2048 in the KBS <-> KMS leg today.
**Red team (attack)**: KBS trust anchor factored → unseal keys for any attested workload; CoCo's security model collapses. Redundant with SGX/TDX break but covers the orchestrator-layer trust.
**Blue team (defense/recovery)**: CoCo is cloud-native; ML-DSA and ML-KEM support in tree. Fleet rotation possible.
**Impact**:
- $: Low billions (emerging market)
- Lives: None direct
- Environment: None direct
- Geopolitical: K8s confidential-workloads sovereignty (EU sovereign cloud, Gaia-X)
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=4, Recoverability=4.

### azure-attestation-jwt
**Context**: Microsoft Azure Attestation Service issues JWTs signed with RSA-2048 over attestation quotes for SGX/TDX/SEV-SNP/TPM/VBS; consumed by Azure Key Vault HSM and Microsoft Purview DLP for release-policy enforcement.
**Red team (attack)**: Factor MAA signing key (published via JWKS); forge attestation JWTs to unseal any attestation-gated Key Vault secret across every Azure tenant. One-key-breaks-all-tenants.
**Blue team (defense/recovery)**: Microsoft rotates MAA signing keys routinely; PQ JWS via ML-DSA is on the Azure roadmap. Operator response is fast once detected.
**Impact**:
- $: Tens of billions
- Lives: None direct
- Environment: None direct
- Geopolitical: US-hyperscaler tenant sovereignty
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=4.

### aws-iot-device-certs
**Context**: AWS IoT Core uses X.509 RSA-2048 device certs (or ECC) for mutual-TLS; ~tens of billions of devices including energy telematics, fleet telematics, consumer IoT, ICS gateways.
**Red team (attack)**: Factor Amazon Root CA 1 (RSA-2048) or customer-issued sub-CAs; impersonate devices, publish bogus telemetry/commands on MQTT topics for fleets of EV chargers, solar inverters, industrial sensors. "Aurora"-class regional grid event plausible via inverter fleet.
**Blue team (defense/recovery)**: AWS has Amazon Trust Services roots 3-6 on ECDSA; migration is device-side, throttled by firmware cadence for OT gear. Cert renewal automation helps.
**Impact**:
- $: Tens of billions
- Lives: Medical IoT, connected vehicles
- Environment: Solar inverter / DER grid disturbance scenario
- Geopolitical: AWS-US; sovereign-IoT alternatives (Huawei, Alibaba) compete
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=3.

### scep-mdm
**Context**: Simple Certificate Enrollment Protocol over RSA for MDM (Jamf, Intune, Workspace ONE, Kandji) auto-enrolls device certs on millions of managed Apple/Android/Windows endpoints. Enrollment-CA keys are MDM-tenant-held.
**Red team (attack)**: Factor MDM tenant enrollment CA; mint device certs for any identity, enroll rogue devices into conditional-access policies, bypass VPN/Wi-Fi controls in enterprise. CVE-2025-class device-impersonation at scale.
**Blue team (defense/recovery)**: MDM vendors can reissue enrollment CAs; all devices must re-enroll (painful). ACME-over-SCEP and EST-ECC migration ongoing.
**Impact**:
- $: Tens of billions
- Lives: Healthcare MDM fleets
- Environment: None direct
- Geopolitical: US-centric vendors
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=3.

### adcs-windows
**Context**: Microsoft AD Certificate Services (ADCS) is the default enterprise PKI inside ~every Windows domain (banks, hospitals, government, military); issues RSA-2048/4096 certs for smartcard logon, IPsec, 802.1X, document encryption. Roots often 20-year RSA-4096.
**Red team (attack)**: Factor an enterprise ADCS root (cert is available to every domain member); issue smartcard-logon certs as Domain Admin via PKINIT — instant domain takeover. ESC1-ESC15 on steroids.
**Blue team (defense/recovery)**: Microsoft ships PQ ADCS via Windows Server 2025+; rotating enterprise roots is a multi-year project per org, re-issuing every user/device cert. Many orgs will never complete it.
**Impact**:
- $: Hundreds of billions (every enterprise IT)
- Lives: Hospital Windows domains
- Environment: Indirect
- Geopolitical: Microsoft-US dominance in enterprise identity
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=1.

### vault-pki
**Context**: HashiCorp Vault PKI secrets engine is the cloud-native PKI mint for CI/CD, service-mesh (Consul, Istio via SPIFFE), Kubernetes workload identities; predominantly RSA-2048/3072 intermediates, RSA-4096 roots.
**Red team (attack)**: Factor Vault intermediate (cert is issued to every mesh workload and visible in traffic); mint arbitrary SPIFFE IDs, impersonate any service in mTLS mesh. Microservice trust model collapses.
**Blue team (defense/recovery)**: Vault supports ECDSA/Ed25519 since 1.10 and ML-DSA roadmap 2026; operator-initiated re-issuance is the norm, mesh rolls the cert automatically.
**Impact**:
- $: Tens of billions (modern-cloud tenants)
- Lives: None direct
- Environment: None direct
- Geopolitical: Largely US-enterprise; sovereign SPIFFE (SPIRE + Keyfactor) gains
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=4.

### kubernetes-kubeadm
**Context**: `kubeadm init` generates RSA-2048 cluster-CA, etcd-CA, front-proxy-CA; every K8s API call is mTLS-authenticated against these. Also ServiceAccount JWT signer default RSA-2048.
**Red team (attack)**: Factor a cluster CA (cert is on every kubelet/node, readable); mint admin certs or SA tokens, exec into every pod, exfiltrate every Secret. Entire cluster tenancy compromised.
**Blue team (defense/recovery)**: kubeadm 1.31+ allows ECDSA certs; re-issuance is `kubeadm certs renew` but CA rotation is hands-on. Service mesh + OIDC issuer migration required.
**Impact**:
- $: Hundreds of billions (modern SaaS/cloud)
- Lives: None direct
- Environment: None direct
- Geopolitical: Global
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=4, Recoverability=3.

### sigstore-model-signing
**Context**: Sigstore Cosign + model-signing for ML artefacts (Hugging Face, PyPI attestations) uses Fulcio-issued RSA/ECDSA certs with transparency via Rekor; growing rapidly as SLSA-L3 norm.
**Red team (attack)**: Factor Fulcio root (published, ECDSA by default but RSA fallback exists); forge signed attestations for any artefact identity. RSA path is narrower; if Fulcio is ECDSA-only, it survives.
**Blue team (defense/recovery)**: Sigstore is ECDSA-primary and ML-DSA roadmapped. The RSA exposure is in legacy Cosign signatures over registries.
**Impact**:
- $: Low billions (OSS supply-chain incremental)
- Lives: None direct
- Environment: None direct
- Geopolitical: Open-source commons
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=4.

### huggingface-commit-signing
**Context**: Hugging Face repo commit signing + model-signing via RSA-GPG keys bound to HF accounts; signs model weights for ~1M repos including frontier open-weights (Llama, Mistral, DeepSeek).
**Red team (attack)**: Factor high-profile maintainer keys, push malicious weights under trusted identity — poison models consumed by enterprises into production. Harder to detect than traditional supply-chain.
**Blue team (defense/recovery)**: HF is migrating to sigstore + Ed25519; rebuild integrity metadata across legacy repos. Consumer responsibility to re-verify.
**Impact**:
- $: Tens of billions (AI dependency supply-chain)
- Lives: Models deployed in medical triage, legal LLMs
- Environment: None direct
- Geopolitical: HF is French; frontier-weights integrity is a national competition dimension
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3.

### docker-notary-tuf
**Context**: Docker Content Trust / Notary v1 + TUF used RSA-2048 for root + snapshot + timestamp keys on Docker Hub official images (deprecated but still present for many legacy tags); newer Notary v2 is ECDSA.
**Red team (attack)**: Factor Docker Hub root key (rarely rotated) — push malicious official images (nginx, redis, alpine) under trusted tags across millions of `docker pull` flows.
**Blue team (defense/recovery)**: Notary v2 + ORAS adoption; retire v1 entirely. Docker Hub already deprecating.
**Impact**:
- $: Tens of billions
- Lives: None direct
- Environment: None direct
- Geopolitical: Docker-US
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=3.

### git-signed-commits
**Context**: GPG/SSH-signed git commits/tags under RSA-4096 (per-maintainer keys) gate merges on GitHub/GitLab "verified" badges and release-signing workflows. Kernel maintainers, crypto libs, major OSS depend on this.
**Red team (attack)**: Factor a maintainer key (public via keyserver), forge signed commits/tags on upstream mirrors or merge via compromised hosting. Everyone downstream sees "verified."
**Blue team (defense/recovery)**: Shift to SSH-signed commits with Ed25519 (already widespread); GitHub can pivot "verified" semantics. Historical commits stay "verified" under dead keys.
**Impact**:
- $: Tens of billions
- Lives: Downstream OSS in medical/ICS
- Environment: None direct
- Geopolitical: OSS commons
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=3.

### swift-financial
**Context**: SWIFT FIN/MX messaging uses RSA (in LAU, RMA, and SWIFT PKI) — the messaging rail for ~$150T/year of interbank transfers across 11,000+ institutions. HSMs sign/verify message authentication and counterparty-relationship establishment.
**Red team (attack)**: Factor the SWIFT root CA or a member-bank's HSM key; forge MT103/MT202 (Bangladesh Bank-style) at will across the network, bypassing RMA because counterparty trust is cryptographic. $1B-scale heists per incident, repeated.
**Blue team (defense/recovery)**: SWIFT is piloting PQ (ML-KEM/ML-DSA) in CSP 2024-2026; rekey is mandatory across members. Incident response involves literal cable bank-to-bank contact verifications.
**Impact**:
- $: Trillions (rail failure, not per-fraud)
- Lives: Foreign-aid payment chains
- Environment: None direct
- Geopolitical: Belgian-hosted but US-policy-pressured; sanctioned nations (RU/IR) would exploit instantly
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=2. The top global-finance rail.

### fix-cme-exchange
**Context**: CME, ICE, Eurex, CBOE FIX gateway mTLS over RSA-2048; ~$6T daily notional on CME Group alone. Market-maker firms authenticate with member certs.
**Red team (attack)**: Factor exchange-issued member certs; impersonate member, submit/cancel orders ahead of NBBO or spoof to trigger stop cascades. "Flash-crash weaponized."
**Blue team (defense/recovery)**: Exchanges issue new certs on ECDSA; members must re-provision. Trading halts during migration.
**Impact**:
- $: Trillions (market integrity)
- Lives: Pension funds
- Environment: None direct
- Geopolitical: US-exchange dominance; CN/EU exchanges would pivot
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3.

### emv-payment-cards
**Context**: EMV chip-and-PIN cards use RSA-1024/2048 for offline data authentication (SDA/DDA/CDA) and RSA-2048 for issuer-ICC CA; Visa/Mastercard/AmEx scheme roots sign issuer CAs for ~5B cards.
**Red team (attack)**: Factor scheme root or issuer CA; mint counterfeit chip cards that authenticate offline (airlines, transit, rural POS). Fraud limited at online-auth terminals but catastrophic for offline/hybrid.
**Blue team (defense/recovery)**: EMVCo has a PQ roadmap (ML-DSA, late-2020s); card reissuance cycles are 3-4 years. Scheme CA rotation is an EMVCo-coordinated protocol change.
**Impact**:
- $: Hundreds of billions (fraud surge + reissuance)
- Lives: Indirect
- Environment: Card-plastic waste
- Geopolitical: Visa/MC (US), UnionPay (CN), JCB (JP)
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=3, Recoverability=2.

### pos-pci-pts
**Context**: PCI PIN Transaction Security (PTS) POS terminals (Ingenico, Verifone, PAX) use RSA remote key-loading (RKL) for DUKPT/3DES key injection; PCI-PIN Security Requirements mandate RSA ≥2048 for the scheme.
**Red team (attack)**: Factor terminal-vendor RKL CA or acquirer injection key; inject chosen DUKPT base keys into terminals, harvest plaintext PINs from every swipe/dip. Millions of PINs across retailers.
**Blue team (defense/recovery)**: PCI SSC has ML-KEM scope for next-gen; terminal fleet re-injection is physical per-device. Industry-wide 3-year project.
**Impact**:
- $: Tens of billions (PIN exposure + fraud)
- Lives: None direct
- Environment: None direct
- Geopolitical: US card schemes dominant
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=4, Stealth=4, Recoverability=3.

### hbci-fints-banking
**Context**: German/Austrian HBCI/FinTS retail banking protocol uses RSA-2048 for client-bank signing (HBCI-DDV/RDH cards); ~40M users across Sparkassen, Volksbanken, Commerzbank.
**Red team (attack)**: Factor bank-issuer or root keys; forge SEPA transfers from customer accounts. Less catastrophic than SWIFT but touches retail accounts directly.
**Blue team (defense/recovery)**: ZKA pushes updates; card reissuance ~5yr cycle. German BaFin oversight drives slow migration.
**Impact**:
- $: Billions (retail-fraud sized)
- Lives: None direct
- Environment: None direct
- Geopolitical: DE/AT banking sovereignty
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### atm-xfs-firmware
**Context**: CEN/XFS ATM firmware and remote-key-download (NDC/DDC) uses RSA-2048 for NCR/Diebold/Hyosung cash handlers; ~1M ATMs worldwide.
**Red team (attack)**: Factor vendor firmware-signing key; push malicious FW to ATMs enabling "jackpotting" (cash-out) at scale, or RKD-hijack to harvest PINs. Carbanak / Cobalt Group wet dream.
**Blue team (defense/recovery)**: Vendors rotate keys + ship new FW via certified-engineer visits (slow); fleet migration is 18-24 months.
**Impact**:
- $: Tens of billions (cash losses + remediation)
- Lives: None direct
- Environment: None direct
- Geopolitical: Ransomware-regime actors (RU, DPRK) benefit directly
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3.

### ibm-icsf-mainframe
**Context**: IBM z/OS ICSF Integrated Cryptographic Service Facility (CCA + PKCS#11) wraps every large-bank core banking key; RSA-2048/4096 for PKA keys. 80% of global-bank core banking + many insurers.
**Red team (attack)**: Factor master keys issued from the Crypto Express HSM; forge signatures on any bank-authority workflow — GL tampering, signed fund transfers. Requires privileged logical access first, but crypto breaks the last barrier.
**Blue team (defense/recovery)**: IBM has Crypto Express 8S with ML-DSA/ML-KEM; mainframe migration requires z/OS 3.1+ and tenant re-keying. Multi-year bank-IT project.
**Impact**:
- $: Trillions (core banking ledger integrity)
- Lives: Indirect via payroll/benefits
- Environment: None direct
- Geopolitical: IBM-US concentration of financial-system crypto
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=2.

### windows-dpapi
**Context**: Windows Data Protection API derives per-user/machine master keys wrapped under RSA-2048 key pairs held in LSASS/DC; protects browser passwords, VPN creds, BitLocker recovery keys, EFS, DPAPI-NG. Every Windows endpoint + every AD backup key.
**Red team (attack)**: Factor the domain DPAPI backup key held by DCs (recovered via dpapi::backupkey DCSync-class tooling + the published RSA-2048 cert); decrypt every user's DPAPI blobs across history. Browser-password exfil at fleet scale.
**Blue team (defense/recovery)**: Microsoft ML-DSA/ML-KEM for DPAPI roadmapped in Windows Server 2025+; backup-key rotation is done but historic blobs stay vulnerable.
**Impact**:
- $: Hundreds of billions (every credentialed user in every AD)
- Lives: None direct
- Environment: None direct
- Geopolitical: Microsoft-US endpoint credential monoculture
**Ranking**: Criticality=5, Exploitability=5, BlastRadius=5, Stealth=5, Recoverability=2.

### usps-imi-indicia
**Context**: USPS Information-Based Indicia Program uses RSA-1024 (yes, still) for postage-meter indicia signatures; ~$14B/year of metered postage. Also UPU global postage frameworks.
**Red team (attack)**: Factor USPS or meter-vendor key; print unlimited fraudulent prepaid indicia at scale. USPS revenue loss directly.
**Blue team (defense/recovery)**: USPS IBIP 2.0 roadmap to PQ; meter fleet replacement 5+yr cycle.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: Paper waste
- Geopolitical: USPS only; UPU follows
**Ranking**: Criticality=2, Exploitability=5, BlastRadius=2, Stealth=3, Recoverability=4.

### rfc3161-tsa-timestamp
**Context**: RFC 3161 Time-Stamp Authorities (DigiCert, GlobalSign, Sectigo, FreeTSA, Microsoft, Apple, Adobe) sign timestamps under RSA-2048/3072 for code-signing (Authenticode countersignatures), PDF/A-3 long-term signatures, eIDAS qualified timestamps.
**Red team (attack)**: Factor TSA signing key; backdate malicious signed binaries to pre-revocation ("evasion of revocation"), invalidate long-term-validation chains on PDF signatures. Legal-evidentiary chaos.
**Blue team (defense/recovery)**: eIDAS regulation already pushes PQ timestamps; CA/B forum follows. Replace TSA keys and re-issue archived timestamps where possible. Historical is lost.
**Impact**:
- $: Tens of billions (legal/contract archives)
- Lives: None direct
- Environment: None direct
- Geopolitical: EU Trust Service Providers sovereignty
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3.

### esim-gsma
**Context**: GSMA eSIM SGP.22 uses RSA + ECDSA in the CI/SM-DP+/SM-DS chain; GSMA CI root signs operator SM-DP+ certs for eSIM profile download to billions of consumer + industrial (eUICC IoT) devices.
**Red team (attack)**: Factor a CI-chain cert; mint rogue SM-DP+ and push malicious operator profiles to eSIMs — arbitrary IMSI/Ki injection, surveillance at scale. iPhone/Pixel eSIM fleets impacted.
**Blue team (defense/recovery)**: GSMA SGP.32 IoT variant and CI migration to ECDSA/ML-DSA (in flight); OS updates for device side. Trust-anchor refresh in device-ROM is the tail.
**Impact**:
- $: Tens of billions
- Lives: Connected medical, auto telematics
- Environment: Connected-vehicle and industrial IoT
- Geopolitical: GSMA is a global cartel; CN telecoms gain leverage via domestic eSIM CI
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=5, Stealth=4, Recoverability=2.

### docsis-bpi-cable
**Context**: CableLabs DOCSIS 3.1/4.0 BPI+ uses RSA-1024/2048 for cable-modem certs (CM-CA/CVC-CA); ~100M residential cable modems in North America + global deployments (Comcast, Charter, Cox, Rogers, Vodafone cable).
**Red team (attack)**: Factor DOCSIS Root CA (CableLabs); clone cable-modem certs, evade class-of-service limits, join any MSO's DOCSIS backhaul. Throughput theft is commercial; network-probe is the real risk.
**Blue team (defense/recovery)**: DOCSIS 4.0 PQ extensions in CableLabs roadmap; MSO gradually replaces modems (5+yr cycle).
**Impact**:
- $: Low billions (MSO revenue impact)
- Lives: None direct
- Environment: None direct
- Geopolitical: US cable MSO dominance; Vodafone/Liberty in EU
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=4.

### cbrs-sas-spectrum
**Context**: FCC CBRS (3.55-3.7 GHz) SAS operators (Google, CommScope, Federated Wireless, Sony) authenticate CBSDs with RSA-2048 device certs; millions of small-cell / private-5G / fixed-wireless endpoints.
**Red team (attack)**: Factor SAS-issuer CA; forge CBSD certs, inject spectrum interference or false measurement data to mis-coordinate the dynamic sharing with DoD Navy radar. Navy-radar-coordination failure is the sting.
**Blue team (defense/recovery)**: SAS operators rotate; fleet update over FWA cadence. WInnForum spec update required for PQ.
**Impact**:
- $: Low billions
- Lives: Naval radar coordination edge case
- Environment: RF interference
- Geopolitical: DoD-CBRS sharing is a US-specific regulatory success; failure embarrasses FCC/NTIA
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=4.

### dvb-ci-pay-tv
**Context**: DVB-CI+ CAMs (Nagra, Conax, Irdeto, Verimatrix, NDS/Synamedia) use RSA-2048 for host-CAM authentication and content-key distribution; ~1B pay-TV subscribers worldwide.
**Red team (attack)**: Factor CAM-vendor RSA key; mass piracy, operator revenue loss in the $B/year. Pay-TV operators (Sky, DirecTV, Canal+) incensed.
**Blue team (defense/recovery)**: DVB-PQ extension in discussion; STB fleets replaced over 7-10yr cycles.
**Impact**:
- $: Tens of billions (lost subscriber revenue)
- Lives: None direct
- Environment: STB e-waste
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### atsc3-broadcast
**Context**: ATSC 3.0 (NextGen TV) uses RSA-2048 for Broadcast-PKI signing of emergency-alert ARWARN overrides, OTA interactive-app signing, and content-signing. FCC + broadcasters deploying widely.
**Red team (attack)**: Factor an ATSC 3 signing key; push forged EAS-equivalent emergency overrides to millions of TVs (panic, false evacuation), or push malicious HTML apps into receiver's broadcast-web runtime.
**Blue team (defense/recovery)**: ATSC is iterating on PQ profiles; receiver-FW update OTA possible.
**Impact**:
- $: Billions (recall + broadcaster remediation)
- Lives: Potential panic/evacuation casualties from forged EAS
- Environment: None direct
- Geopolitical: US + KR broadcast sovereignty
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=3, Recoverability=3.

### iec62443-dtls-ot
**Context**: IEC 62443-4-2 OT zone boundaries use RSA-2048 certs in DTLS/TLS between PLCs, HMIs, engineering workstations; Rockwell, Siemens, Schneider, ABB, Honeywell, Emerson all default RSA today.
**Red team (attack)**: Factor a plant's engineering-workstation CA or vendor device CA; forge PLC-vendor engineering creds, push logic changes, cause controlled unsafe state. Triton/Trisis pattern but via crypto break.
**Blue team (defense/recovery)**: IEC 62443 PQ profile in draft; plant certs rotatable, device ROM keys not. Ten-year OT upgrade cycles.
**Impact**:
- $: Tens of billions (downtime + remediation)
- Lives: Direct — plant safety
- Environment: Chemical / energy releases
- Geopolitical: Global vendor mix
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=1.

### dnp3-scada
**Context**: IEEE 1815 DNP3 Secure Authentication v5/v6 uses RSA-2048 for update-key distribution to substations, water, gas SCADA; NERC CIP-005 / CIP-007 leverage it. ~10,000 US utility SCADA systems.
**Red team (attack)**: Factor a utility's DNP3-SA key distribution authority; inject malicious SCADA commands (open breakers, trip units) bypassing challenge-response. Regional blackout scenario.
**Blue team (defense/recovery)**: IEC 62351 PQ direction; RTU firmware upgrades are slow (7-10 yr). NERC has PQ roadmap in draft.
**Impact**:
- $: Tens of billions (outage + damage)
- Lives: Hospital/cold-chain outage casualties
- Environment: Cascade failure
- Geopolitical: US/CA grid sovereignty vs state actors
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=4, Recoverability=2.

### iec62351-substation
**Context**: IEC 62351 secures IEC 61850 GOOSE/SV/MMS with RSA-2048 certs for transmission-substation automation; every transmission utility worldwide.
**Red team (attack)**: Factor substation-vendor (Siemens SICAM, GE Multilin, ABB, SEL) or utility CA; inject GOOSE/SV to trip protection relays — Ukraine-grid-attack class.
**Blue team (defense/recovery)**: IEC TC57 WG15 drafting PQ profile; retrofit is substation-by-substation.
**Impact**:
- $: Tens of billions
- Lives: Grid-outage casualties
- Environment: Cascade effects
- Geopolitical: High (CN/RU state-actor interest in transmission)
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=1.

### hydrodam-scada
**Context**: USBR, USACE, BPA, TVA, Hydro-Québec, EDF use RSA-2048 in signed SCADA for spillway/turbine/gate control; ~5000 large dams.
**Red team (attack)**: Factor utility/integrator CA; override spillway/gate commands — uncontrolled release causing downstream flooding, or turbine over-speed destruction. Oroville-class potential.
**Blue team (defense/recovery)**: Same as substation; retrofit per-dam.
**Impact**:
- $: Low billions (damage)
- Lives: Mass-casualty flood scenario
- Environment: Downstream ecological catastrophe
- Geopolitical: High-value infrastructure
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=4, Stealth=4, Recoverability=2.

### siemens-s7-tia
**Context**: Siemens TIA Portal + S7-1500/1200 PLCs use RSA-2048 for "Know-how protection" + firmware + access-protection signatures; thousands of plants worldwide including many Stuxnet-era targets (Natanz, pharma, auto).
**Red team (attack)**: Factor Siemens firmware signing root (published in TIA DLLs) or project-signing keys; push malicious S7 logic to every S7-1500, repeat Stuxnet against modern centrifuges/lines.
**Blue team (defense/recovery)**: Siemens has PQ in S7-1500 V4 roadmap; fleet upgrade 5+yr. CERT@VDE + BSI coordinated advisory.
**Impact**:
- $: Tens of billions
- Lives: Pharma/water/chemical safety
- Environment: Process-safety releases
- Geopolitical: Siemens-DE global PLC dominance; state-actor kinetic-equivalent
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=5, Recoverability=1.

### opcua-open62541
**Context**: OPC UA (IEC 62541) uses RSA-2048 for client-server mutual auth across every modern plant floor; open62541, Prosys, Unified Automation stacks. Factories, smart buildings, edge-analytics.
**Red team (attack)**: Factor plant/vendor CA; impersonate controller or SCADA client, inject setpoints.
**Blue team (defense/recovery)**: OPC Foundation PQ extensions in v1.05+; gradual rollout.
**Impact**:
- $: Tens of billions
- Lives: ICS safety
- Environment: Plant releases
- Geopolitical: EU/US industrial
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=2.

### ros2-sros2-dds
**Context**: ROS 2 SROS2 uses RSA-2048 in DDS-Security for robot-system auth; widely deployed in research, autonomous trucks, warehouse robots, some DoD programs.
**Red team (attack)**: Factor fleet CA; inject commands, steer autonomous platforms.
**Blue team (defense/recovery)**: DDS-Security PQ TC underway; fleet software update feasible.
**Impact**:
- $: Billions
- Lives: Direct (autonomous robot collisions)
- Environment: None direct
- Geopolitical: US DoD Roboteam interest
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=4.

### refinery-sis-iec61511
**Context**: Safety Instrumented Systems (Triconex, HIMA, Yokogawa ProSafe-RS, Emerson DeltaV-SIS) under IEC 61511 sign SIL-rated logic and PST results with RSA-2048.
**Red team (attack)**: Factor vendor or plant SIS CA; push logic bypassing safety trips — Texas City, Buncefield-class events at scale.
**Blue team (defense/recovery)**: Vendor PQ slow (SIL re-certification); plant-by-plant.
**Impact**:
- $: Billions (per plant)
- Lives: Direct mass-casualty (refinery fires/explosions)
- Environment: Major releases (benzene, HF, sour gas)
- Geopolitical: Operators global; sabotage attribution difficult
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=4, Stealth=5, Recoverability=1.

### pipeline-api1164
**Context**: API 1164 signed leak-detection and pipeline SCADA signing; Colonial Pipeline, Enbridge, Kinder Morgan; TSA Security Directive 2 post-Colonial.
**Red team (attack)**: Factor operator CA; disable/mask leak-detection, override SCADA to pressurize segments — spill + rupture. Colonial v2 by state actor.
**Blue team (defense/recovery)**: TSA pushing PQ in SD-2 revisions; field RTU upgrades slow.
**Impact**:
- $: Tens of billions
- Lives: Direct (rupture casualties)
- Environment: Major spills
- Geopolitical: US/CA pipeline security
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=4, Recoverability=1.

### oilrig-bop-mux
**Context**: BOP stacks, subsea MUX control pods, shear-ram command signing under RSA-2048/3072 (Cameron/SLB, NOV, Aker, TechnipFMC). Signed pod firmware, OIM+company-man two-person auth, RTM uplink; Macondo-post regulatory regime.
**Red team (attack)**: Factor BOP OEM FW root → malicious pod FW silently disables last-line barrier (Macondo-class blowout without insider); factor rig-contractor OIM root → spurious shear-ram destroys pipe/well ($100M event); factor company-man root → forged co-sig bypasses two-person.
**Blue team (defense/recovery)**: BSEE must pre-approve FW changes (30 CFR 250.734); re-cert is years. PQ migration requires MUX vendor + rig operator + regulator alignment.
**Impact**:
- $: Tens of billions (blowout + fleet drilling restrictions)
- Lives: Direct rig-worker + downstream
- Environment: Catastrophic (Macondo-class spill)
- Geopolitical: BSEE/PSA/ANP/NOPSEMA sovereignty over national OCS
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=1.

### water-wima-scada
**Context**: AWWA G430/G440 secure SCADA for water/wastewater utilities, WIMA/WaterISAC; RSA-2048 in most SCADA vendor stacks (Schneider, Rockwell, Emerson).
**Red team (attack)**: Factor utility/vendor CA; override chlorination/fluoride dosing or flood-control gate logic — Oldsmar-style but fleet-wide. Public-health emergency.
**Blue team (defense/recovery)**: AWWA + CISA guidance for PQ; small-utility IT maturity is low.
**Impact**:
- $: Billions
- Lives: Direct (waterborne illness mass-exposure)
- Environment: Watershed contamination
- Geopolitical: Small utilities are soft targets
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=2.

### ami-dlms-cosem
**Context**: Smart-meter AMI under IEC 62056 DLMS/COSEM with RSA-2048 in many European/LatAm/AU deployments (Iskraemeco, Landis+Gyr, Itron, Kaifa); ~1B meters globally.
**Red team (attack)**: Factor utility meter CA; send mass disconnect commands, create sudden load imbalance (grid-frequency event), or manipulate billing data.
**Blue team (defense/recovery)**: DLMS-UA ML-DSA profile in flight; meter fleets replaced 15-20yr.
**Impact**:
- $: Tens of billions
- Lives: Indirect (outage)
- Environment: Grid disturbance
- Geopolitical: Global AMI rollouts; Aurora-style attack possible
**Ranking**: Criticality=5, Exploitability=4, BlastRadius=5, Stealth=4, Recoverability=1.

### vestas-wind-turbine
**Context**: Vestas, GE, Siemens-Gamesa, Goldwind, Envision wind-turbine SCADA + OTA firmware signing under RSA-2048. ~500GW global installed fleet.
**Red team (attack)**: Factor OEM FW signing key; push malicious pitch/yaw or over-speed controls, destroy turbines ($3M each) at fleet scale.
**Blue team (defense/recovery)**: OEM staged rollout; turbine controllers upgradable but unsigned-FW-rollback risk exists for legacy.
**Impact**:
- $: Tens of billions
- Lives: Indirect
- Environment: Grid decarbonization disrupted
- Geopolitical: CN (Goldwind, Envision) gain leverage; US IRA-era fleet exposed
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=2.

### osisoft-pi-historian
**Context**: AVEVA/OSIsoft PI Historian + PI Server mTLS with RSA-2048 in tens of thousands of plant process-data repositories; half of Fortune 500 industrial has PI.
**Red team (attack)**: Factor PI Asset Framework CA; tamper historian data (regulatory compliance fraud) or pivot from PI to ICS via AF connectors.
**Blue team (defense/recovery)**: AVEVA ships ECC/PQ updates; plant-by-plant.
**Impact**:
- $: Low billions
- Lives: Indirect
- Environment: Compliance-data integrity
- Geopolitical: UK-AVEVA (Schneider-owned)
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=4, Recoverability=3.

### fanuc-robot
**Context**: FANUC, KUKA, ABB, Yaskawa industrial robots sign controller firmware + safety-controller (DCS) with RSA-2048; ~4M industrial robots installed.
**Red team (attack)**: Factor vendor FW root; push malicious trajectories, disable safety-rated monitored stop / speed-and-separation. Operator injury scenarios multiplied across plants.
**Blue team (defense/recovery)**: FANUC CNC software modernization cycle ~10yr; PQ roadmaps nascent.
**Impact**:
- $: Billions
- Lives: Direct (operator collisions)
- Environment: None direct
- Geopolitical: JP (FANUC, Yaskawa), DE (KUKA now CN-owned), SE (ABB)
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=2.

### nuclear-iec61513
**Context**: Class-1E safety-I&C (Framatome TXS, Westinghouse Common Q, Rolls-Royce Spinline, MELTAC) under IEC 61513/IEEE 7-4.3.2/NRC RG 1.152; RSA-2048/3072 signs RPS/ESFAS application loads, MoC parameter changes, fuel-handling steps, surveillance completions. ~440 commercial reactors.
**Red team (attack)**: Factor vendor safety-I&C root → attacker-loaded RPS software in vulnerable units — the single most severe identifiable crypto-failure scenario in this catalog, multi-country nuclear-safety regulatory crisis. Factor utility engineering root → forged MoCs slide RPS setpoints (tech-spec envelope mitigates but erodes safety margin), forged fuel steps violate criticality-safety. Factor NRC/ASN qual root → regulatory-qualification authenticity destroyed; fleet operating restrictions pending manual reverification. Factor surveillance signing → tech-spec LCO evidentiary chain collapses.
**Blue team (defense/recovery)**: IEC 61513/IEEE 7-4.3.2 reference specific cryptographic assurance — license-basis changes require regulator pre-approval; post-Fukushima scrutiny at max. No utility wants to be the PQ pilot. Diverse/hard-wired crypto in TXS cycle-critical paths mitigates but not administrative/downloadable-parameter paths. Recovery: fleet-wide shutdown + manual reverification of every plant Q-file.
**Impact**:
- $: Hundreds of billions (fleet shutdown + re-attestation; $250k/day NRC CALs accumulate)
- Lives: Catastrophic potential (RPS bypass in vulnerable unit) + indirect (grid loss)
- Environment: Worst-case — core-damage release; best-case — massive outage carbon-backfill
- Geopolitical: Multi-country regulator crisis (NRC/ASN/ONR/STUK/CNSC/NRA/NNSA/Rostechnadzor) — civilian-nuclear program credibility
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=1. The single worst scenario in the catalog.

### nuclear-iec62645
**Context**: IEC 62645 nuclear cybersecurity framework extends 61513; RSA-2048 in operator cyber-program attestations under 10 CFR 73.54.
**Red team (attack)**: Factor utility cyber-program signing → falsify compliance posture, hide incidents from NRC inspections.
**Blue team (defense/recovery)**: Administrative (not safety-path); document rebuild.
**Impact**:
- $: Low billions ($250k/day NRC CAL accumulation)
- Lives: Indirect
- Environment: Indirect
- Geopolitical: NRC audit-authority credibility
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=5, Recoverability=3.

### iaea-safeguards
**Context**: IAEA safeguards attribute-tagging + C/S (Containment/Surveillance) data signing under RSA-2048 from IAEA HQ (Vienna) → inspected facilities. Nuclear-nonproliferation monitoring chain.
**Red team (attack)**: Factor IAEA safeguards signing key; forge inspector-attribute tags, fake C/S records — enable covert SQ (Significant Quantity) diversion undetected. NPT verification chain collapses.
**Blue team (defense/recovery)**: IAEA moves slowly; member-state trust is the asset. PQ roadmap (IAEA IT Department 2025+).
**Impact**:
- $: None direct
- Lives: Indirect (proliferation → war)
- Environment: Catastrophic if proliferation enabled
- Geopolitical: NPT regime collapse — the worst non-kinetic geopolitical scenario
**Ranking**: Criticality=5, Exploitability=2, BlastRadius=5, Stealth=5, Recoverability=2.

### link16-mids
**Context**: Link 16 / MIDS tactical data link uses mix of hardware-keyed SLS/EHF crypto; RSA appears in MIDS terminal firmware signing, CVSD key distribution at theatre level (SKL-A/B, MIDS-LVT).
**Red team (attack)**: Factor MIDS vendor FW root; push malicious SA/TA ops to terminals, degrade blue-force tracking, enable blue-on-blue. Terminal re-flash requires depot access, so sustainment-chain attack.
**Blue team (defense/recovery)**: DoD has PQ roadmap under CNSA 2.0 (ML-KEM/ML-DSA mandatory in NSS by 2035); MIDS Block Upgrade 2 includes PQ.
**Impact**:
- $: Low billions
- Lives: Direct (combat)
- Environment: None direct
- Geopolitical: NATO coalition interop
**Ranking**: Criticality=4, Exploitability=2, BlastRadius=3, Stealth=4, Recoverability=3.

### galileo-osnma
**Context**: Galileo Open Service Navigation Message Authentication uses ECDSA but falls back to RSA root-key distribution in some ground-segment paths; GPS Chimera has similar patterns.
**Red team (attack)**: Factor OSNMA root (if RSA), forge authenticated nav messages — spoof GNSS-PNT for civilian/commercial users (maritime nav, aviation ILS augments).
**Blue team (defense/recovery)**: GSA has PQ roadmap; OSNMA primary is ECDSA so less urgent.
**Impact**:
- $: Low billions
- Lives: Direct (maritime/aviation incidents)
- Environment: Shipping accidents
- Geopolitical: EU space sovereignty; US GPS Chimera in parallel
**Ranking**: Criticality=3, Exploitability=2, BlastRadius=3, Stealth=3, Recoverability=4.

### spacex-autonomous-fts
**Context**: Autonomous Flight Termination System (SpaceX AFTS, ULA Vulcan, Blue Origin) uses signed onboard crypto for range-safety termination authority; RSA-2048 in current gens.
**Red team (attack)**: Factor AFTS signing key → spurious termination (vehicle loss, $B per launch) or suppressed termination (uncontrolled trajectory; public-safety event).
**Blue team (defense/recovery)**: SpaceX/USSF iterating toward PQ; new vehicles only.
**Impact**:
- $: Billions per incident
- Lives: Catastrophic if AFTS failure in populated overflight
- Environment: Debris
- Geopolitical: US range-safety credibility
**Ranking**: Criticality=4, Exploitability=2, BlastRadius=3, Stealth=3, Recoverability=3.

### aerospace-ccsds
**Context**: CCSDS Space Data Link Security + Secure Commanding use RSA-2048/3072 for satellite TC signing (ESA, NASA, JAXA, commercial — Intelsat, SES, Iridium, Starlink early). ~10k operational sats.
**Red team (attack)**: Factor ground-segment signing key; send malicious TCs to satellites — wobble orbit, burn propellant, attitude-control upset. Satellites are not easily physically-serviceable.
**Blue team (defense/recovery)**: CCSDS has PQ profiles (ML-DSA in CCSDS 355.0); ground-segment-only upgradable, space-segment stuck for mission life.
**Impact**:
- $: Tens of billions
- Lives: Indirect (GPS loss → safety)
- Environment: Kessler-cascade risk
- Geopolitical: Space-sovereignty (US/EU/CN/RU/IN) at risk
**Ranking**: Criticality=4, Exploitability=2, BlastRadius=4, Stealth=5, Recoverability=1.

### faa-remote-id
**Context**: FAA Remote ID (14 CFR Part 89) and ASTM F3411 use RSA/ECDSA signatures for drone ID broadcasts; required on every US commercial/recreational drone above 250g.
**Red team (attack)**: Factor manufacturer signing key; broadcast spoofed Remote IDs, mask drone incursions or falsely attribute flights.
**Blue team (defense/recovery)**: FAA rulemaking; manufacturer FW updates. Mass fleet upgradable via app.
**Impact**:
- $: Low billions
- Lives: Minor (drone-collision evasion)
- Environment: None direct
- Geopolitical: US-specific regulation
**Ranking**: Criticality=2, Exploitability=4, BlastRadius=2, Stealth=3, Recoverability=4.

### avionics-arinc665
**Context**: ARINC 665 / 645 LSAP (Loadable Software Aircraft Part) signing under RSA-2048/3072 for every commercial airliner software load (Boeing, Airbus, Embraer, Bombardier). ~25k airframes globally.
**Red team (attack)**: Factor airframe-OEM or avionics-vendor (Honeywell, Collins, Thales, GE Aviation) signing root; push malicious LSAPs during MRO cycle — hidden unsafe flight-control behavior. Not instant but fleet-wide persistent.
**Blue team (defense/recovery)**: ARINC/RTCA DO-326A/356A cyberworthiness + AMC 20-42; PQ in draft. Airworthiness-Directive-driven software re-cert is years per type.
**Impact**:
- $: Hundreds of billions (fleet groundings + MRO)
- Lives: Direct mass-casualty (jetliner)
- Environment: Major accidents
- Geopolitical: Boeing/Airbus duopoly; FAA/EASA action chaos
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=1.

### acars-cpdlc-datalink
**Context**: CPDLC (Controller-Pilot Data Link) and FANS-1/A over ACARS/VDL Mode 2 use RSA-2048 in newer authenticated variants (ATN/IPS, ED-228A); global oceanic ATC and increasingly continental.
**Red team (attack)**: Factor ANSP signing key; inject false CPDLC clearances to aircraft (descend/climb into conflict). Mass mid-air scenario.
**Blue team (defense/recovery)**: ICAO working PQ for ATN/IPS; FAA/Eurocontrol driving timelines. Slow.
**Impact**:
- $: Low billions
- Lives: Direct mass-casualty
- Environment: None direct
- Geopolitical: ICAO consensus
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=2.

### gmdss-inmarsat
**Context**: Global Maritime Distress and Safety System — Inmarsat C/Fleet Safety + Iridium GMDSS use RSA in SafetyNET II / LRIT / SSAS signed traffic. IMO mandated.
**Red team (attack)**: Factor SafetyNET key; forge MSI (navigational warnings, piracy alerts) or suppress distress; affects every SOLAS vessel.
**Blue team (defense/recovery)**: IMO NCSR working groups; migration 7-10 years.
**Impact**:
- $: Low billions
- Lives: Direct (shipping distress)
- Environment: Maritime spills from missed alerts
- Geopolitical: IMO/Inmarsat/Iridium
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### iho-s63-ecdis
**Context**: IHO S-63 ENC (Electronic Navigational Chart) encryption + RSA-signed cell permits for ECDIS; every SOLAS commercial vessel.
**Red team (attack)**: Factor IHO/hydrographic-office signing key; forge ENC updates with malicious chart data (wrong depths), cause groundings.
**Blue team (defense/recovery)**: IHO S-100 successor standard has PQ hooks; fleet ECDIS upgrades 10+ yr.
**Impact**:
- $: Low billions
- Lives: Direct (grounding casualties)
- Environment: Oil spills from groundings
- Geopolitical: National hydrographic offices
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### submarine-cable-slte
**Context**: Submarine Line Terminal Equipment (SLTE: Ciena, Nokia, Infinera) OAM uses RSA-2048; signed patches + mgmt VPNs for cable-landing stations.
**Red team (attack)**: Factor SLTE vendor mgmt key; alter DWDM channel mapping, tap optical traffic, or cause cable-system outages. Affects 99% intercontinental internet.
**Blue team (defense/recovery)**: Vendor PQ roadmap, cable-landing station access is hard to compromise physically so FW signing is the main vector.
**Impact**:
- $: Tens of billions (internet outage)
- Lives: Indirect (emergency services)
- Environment: None direct
- Geopolitical: US/EU/CN/RU cable-sovereignty battles
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=2.

### p25-otar-radio
**Context**: APCO P25 Phase 2 LMR + OTAR (Over-The-Air Rekeying) KMF uses RSA-2048 for asymmetric rekey to LE/fire/EMS/military radios; ~3M radios globally.
**Red team (attack)**: Factor agency KMF key; push bogus TEKs, disrupt interop at critical incident, or decrypt historic tactical traffic.
**Blue team (defense/recovery)**: Motorola, L3Harris, Tait, Kenwood phasing PQ in P25 Phase 3; radio re-flash via depot.
**Impact**:
- $: Low billions
- Lives: Direct (first-responder comms)
- Environment: None direct
- Geopolitical: Public-safety sovereignty
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### us-ptc-railway
**Context**: FRA-mandated Positive Train Control uses signed onboard/wayside messaging; AAR IEEE 1570 IRAC over RSA-2048 for wayside interface and locomotive message-gateway certs. BNSF, UP, NS, CSX, Amtrak.
**Red team (attack)**: Factor railroad CA; inject PTC messages causing enforcement trips (false emergency brakes) or suppressing enforcement (misaligned switch override). LaChine/Lac-Mégantic-class potential.
**Blue team (defense/recovery)**: FRA has PQ roadmap; interop-class-I rollout multi-year.
**Impact**:
- $: Low billions
- Lives: Direct mass-casualty (collision/derailment)
- Environment: Haz-mat tanker spills
- Geopolitical: US/CA/MX rail
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=2.

### railway-ertms
**Context**: ERTMS/ETCS L2/L3 and Euroradio KMC use RSA-2048 for KMC-RBC certs; all EU high-speed rail + increasing mainline.
**Red team (attack)**: Factor national railway KMC; forge MA (Movement Authority) or emergency stop messages. SNCF, DB, RFI scale outages or incidents.
**Blue team (defense/recovery)**: UIC/ERA pushing PQ in ERTMS baseline 4; infrastructure upgrade 10+ yr.
**Impact**:
- $: Low billions
- Lives: Direct mass-casualty
- Environment: None direct
- Geopolitical: EU rail sovereignty, CN CRH export stack
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=2.

### cbtc-subway
**Context**: Communication-Based Train Control (NYC MTA, London Underground, Paris Metro, HK MTR) uses RSA-2048 in vendor CBTC stacks (Thales Seltrac, Siemens Trainguard, Alstom Urbalis).
**Red team (attack)**: Factor operator/vendor CA; inject movement authorities causing collisions or station overruns.
**Blue team (defense/recovery)**: IEEE 1474 + vendor PQ roadmaps; retrofit per-line multi-year.
**Impact**:
- $: Low billions
- Lives: Direct (rush-hour mass-casualty)
- Environment: None direct
- Geopolitical: Metropolitan
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=2.

### digital-tachograph-eu
**Context**: EU digital tachograph (Regulation 165/2014) + Smart Tachograph Gen 2 use RSA-2048/3072 in the European Root CA (JRC Ispra) for driver/workshop/company/VU cards; every HGV in EU/EEA.
**Red team (attack)**: Factor ERCA RSA key; forge driver cards to falsify driving hours (fatigue-law evasion) or workshop cards to tamper with tachograph. Road-safety erosion at continental scale.
**Blue team (defense/recovery)**: Gen 2 V2 has ECC migration already; PQ roadmap nascent. Card reissuance 5yr cycle.
**Impact**:
- $: Billions
- Lives: Direct (driver-fatigue collisions)
- Environment: Indirect
- Geopolitical: EU transport-sovereignty
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### eu-tachograph-dtco
**Context**: Continental VDO DTCO tachograph + driver-card PKI (closely related to above); DE-specific operator.
**Red team (attack)**: Same as above at vendor scope.
**Blue team (defense/recovery)**: Same.
**Impact**: Same scope narrower.
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### etc-tolling
**Context**: ETC tolling (E-ZPass IAG, EU EETS, Japan ETC 2.0, Australia/NZ Transurban) uses RSA-2048 in OBE certs + back-office signing. Hundreds of millions of transponders.
**Red team (attack)**: Factor issuer CA; clone transponder ID, free tolls; more interestingly — falsify cross-state/country settlement, revenue-leak scheme operators.
**Blue team (defense/recovery)**: Transponder fleets replaced slowly; back-office replace ECDSA easier.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: National/regional
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### iso15118-ev-charging
**Context**: ISO 15118 Plug & Charge uses RSA-2048 in the V2G PKI (Hubject + Autel Energy + CharIN participants) for contract certs and OCPP; EU AFIR mandate + US NEVI.
**Red team (attack)**: Factor V2G root CA; forge contract certs, charge to any EV account (fraud) or — more severe — inject ISO 15118-20 commands as CPO, open unsafe bidirectional flows (V2G) causing grid imbalance.
**Blue team (defense/recovery)**: V2G-PKI governance (VDE-FNN, OCA) rotating; fleet charger + vehicle FW multi-year.
**Impact**:
- $: Tens of billions (EV charging fraud + grid stability)
- Lives: Indirect
- Environment: EV rollout confidence
- Geopolitical: EU transport electrification
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=2.

### evse-iso15118-pnc
**Context**: EVSE (charging stations) Plug-and-Charge subset of above; OCPP 2.0.1 uses mTLS with RSA-2048.
**Red team (attack)**: Same; OCPP backend impersonation of any charger across CSMS.
**Blue team (defense/recovery)**: Same.
**Impact**: Same.
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=2.

### insurance-telematics-ubi
**Context**: Usage-based insurance (Progressive Snapshot, Allstate Drivewise, LexisNexis Nuonic, Octo) uses RSA-2048 in telematics-dongle device certs and back-office signing.
**Red team (attack)**: Factor issuer CA; inject false telematics records to manipulate premiums or forge vehicle-loss data.
**Blue team (defense/recovery)**: Carrier rotation fast; dongle/vehicle-OEM fleet slower.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### john-deere-agtech
**Context**: John Deere Operations Center + JDLink telematics authenticates equipment via RSA-2048 device certs; 2M+ connected machines. Also used for ag data integrity (yield maps).
**Red team (attack)**: Factor JD device CA; brick or remote-control combines/sprayers at harvest (food-supply disruption at scale) — CN-RU state-actor scenario against US breadbasket.
**Blue team (defense/recovery)**: Deere has JDLink Next + PQ roadmap; fleet software update via cellular.
**Impact**:
- $: Tens of billions (harvest disruption)
- Lives: Indirect (food security)
- Environment: Food-supply shock
- Geopolitical: Food-security weapon
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=4, Stealth=4, Recoverability=3.

### komatsu-autonomous-mining
**Context**: Komatsu FrontRunner, Caterpillar Command autonomous haul-truck fleets at Pilbara, Chilean copper etc. sign vehicle + fleet-mgmt comms with RSA-2048.
**Red team (attack)**: Factor fleet CA; steer autonomous 300-ton haul trucks into ore-processing plants or into each other. Catastrophic at mine scale.
**Blue team (defense/recovery)**: Mine-operator-scope PKI; site-by-site replacement.
**Impact**:
- $: Low billions (mine outage)
- Lives: Direct (haul-truck collisions)
- Environment: Local
- Geopolitical: Supply-chain for strategic minerals
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### otis-elevator
**Context**: Otis, Kone, Schindler, Mitsubishi elevator IoT (Otis ONE, Kone 24/7) uses RSA-2048 for controller telemetry + safety-firmware signing. Millions of elevators.
**Red team (attack)**: Factor OEM FW key; push malicious controller logic — disable safety overspeed governors, entrap riders, or cause car-to-shaft collisions.
**Blue team (defense/recovery)**: EN 81-20/50 safety-code re-cert; fleet software update multi-year.
**Impact**:
- $: Billions
- Lives: Direct (entrapment, falls)
- Environment: None direct
- Geopolitical: Global OEMs
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### ski-lift-doppelmayr
**Context**: Doppelmayr/Leitner, Poma, Bartholet ski-lift/gondola control systems sign safety-controller FW with RSA-2048 under TÜV SÜD/EN 13243.
**Red team (attack)**: Factor OEM key; disable emergency brake or manipulate speed envelopes.
**Blue team (defense/recovery)**: TÜV re-cert; fleet upgrade seasonal.
**Impact**:
- $: Low billions
- Lives: Direct (mass-casualty gondola failure)
- Environment: None direct
- Geopolitical: Alpine/resort
**Ranking**: Criticality=3, Exploitability=2, BlastRadius=2, Stealth=3, Recoverability=3.

### medical-device-fda
**Context**: FDA pre-market guidance (2023) + Section 524B require SBOM + signed firmware for medical devices; RSA-2048 is standard across Medtronic, Abbott, Philips, GE Healthcare, Siemens Healthineers, Roche.
**Red team (attack)**: Factor OEM FW key; push malicious insulin pump, pacemaker, ventilator FW at scale. Direct lethal capability.
**Blue team (defense/recovery)**: FDA PMA supplement required; device-by-device recall. Fleet upgrade years.
**Impact**:
- $: Tens of billions
- Lives: Direct, catastrophic (implanted devices, life-support)
- Environment: None direct
- Geopolitical: US medical-device industry
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=5, Stealth=5, Recoverability=1.

### medtronic-cied
**Context**: Medtronic CIED (Cardiac Implantable Electronic Devices: pacemakers, ICDs, LVADs) use RSA-2048 for programmer auth + remote monitoring (CareLink); ~2M active implants.
**Red team (attack)**: Factor Medtronic CIED signing key; deliver malicious FW via programmer or CareLink home monitor — induce lethal shock or program shutdown. Direct assassination capability.
**Blue team (defense/recovery)**: FDA coordinated recall; FW update requires clinic visit for many models. Explantation for older models — surgical risk for millions of patients.
**Impact**:
- $: Billions
- Lives: Direct lethal (patient by patient)
- Environment: None direct
- Geopolitical: Assassination capability at head-of-state scale
**Ranking**: Criticality=5, Exploitability=3, BlastRadius=4, Stealth=5, Recoverability=1.

### illumina-sequencer
**Context**: Illumina NovaSeq/NextSeq sequencer reagent authentication + run signing under RSA-2048; >80% of global NGS capacity. Also used in dx-approved (IVD) platforms.
**Red team (attack)**: Factor Illumina signing key; forge reagent auth (clone cartridges), or — worse — push malicious instrument FW that subtly alters base-calls in cancer dx / newborn screening. Clinical-result integrity collapses.
**Blue team (defense/recovery)**: FDA-cleared IVD re-cert; firmware push via Illumina Connected Analytics.
**Impact**:
- $: Billions
- Lives: Direct (dx errors)
- Environment: None direct
- Geopolitical: US-Illumina dominance; BGI/MGI (CN) gains
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### dscsa-pharma-serialization
**Context**: DSCSA (US), EU FMD, China NMPA serialization; RSA-2048 in ATP EPCIS + GS1 signed events for unit-level pharmaceutical traceability. Operational since 2023-2024.
**Red team (attack)**: Factor manufacturer/3PL signing key; forge serialization records enabling counterfeit distribution at wholesale — opioid fentanyl diversion or oncology-drug counterfeit at scale.
**Blue team (defense/recovery)**: FDA + GS1 governance; CA rotation possible, trading-partner onboarding slow.
**Impact**:
- $: Low billions
- Lives: Direct (counterfeit/adulterated drugs)
- Environment: None direct
- Geopolitical: Global pharma supply
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### hl7-direct-fhir
**Context**: HL7 Direct Project + FHIR Bulk Data uses S/MIME (RSA-2048) for clinical-document exchange between EHRs/HIEs; ONC DirectTrust anchors. ~90% US hospitals.
**Red team (attack)**: Factor DirectTrust bundle or HIE CA; forge C-CDA/FHIR messages — alter lab results, prescriptions at scale. Patient-safety events.
**Blue team (defense/recovery)**: ONC rule for PQ; DirectTrust roots rotatable. Multi-year industry project.
**Impact**:
- $: Low billions
- Lives: Direct (wrong meds/dx)
- Environment: None direct
- Geopolitical: US healthcare
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### dicom-medical-imaging
**Context**: DICOM structured-report signing + TLS for PACS/VNA uses RSA-2048 (GE, Philips, Siemens Healthineers, Canon Medical, Fujifilm); every hospital radiology.
**Red team (attack)**: Factor hospital/vendor CA; tamper radiology reports or images — missed tumors or false positives at scale.
**Blue team (defense/recovery)**: DICOM WG-14 PQ profile; hospital-by-hospital.
**Impact**:
- $: Low billions
- Lives: Direct (missed dx)
- Environment: None direct
- Geopolitical: Global
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### vaccine-coldchain-iot
**Context**: WHO + CDC + Sanofi/Pfizer cold-chain IoT sensors (Sensitech, Elpro) sign temperature logs with RSA-2048; vaccine integrity evidence.
**Red team (attack)**: Factor sensor-vendor CA; forge temperature logs, conceal excursions — release spoiled vaccine doses.
**Blue team (defense/recovery)**: Sensor fleet upgrade possible. WHO/CDC oversight.
**Impact**:
- $: Low billions
- Lives: Direct (spoiled vaccines → outbreak)
- Environment: None direct
- Geopolitical: Global health
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### bloodbank-iso-udi
**Context**: ISBT 128 blood-unit + ISO UDI with RSA-2048 signing for donor/component traceability at AABB member blood banks; global.
**Red team (attack)**: Factor signing authority; forge donor screening records or divert contaminated units. Transfusion-transmitted infection events.
**Blue team (defense/recovery)**: AABB + ICCBBA; slow but possible.
**Impact**:
- $: Low billions
- Lives: Direct (transfusion infections)
- Environment: None direct
- Geopolitical: Global
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### thermofisher-massspec
**Context**: Thermo Fisher, Agilent, Waters, Shimadzu mass-spec + chromatography instruments sign methods + audit trails under RSA-2048 for GxP (21 CFR Part 11) regulated labs.
**Red team (attack)**: Factor instrument FW key; tamper QC/raw data, defeat 21 CFR Part 11 compliance at pharma/biotech.
**Blue team (defense/recovery)**: FDA reauthorization; fleet upgrade.
**Impact**:
- $: Low billions
- Lives: Indirect (drug QA)
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=4, Recoverability=3.

### breathalyzer-dui
**Context**: Intoxilyzer/Draeger evidentiary breathalyzers sign result records with RSA-2048 for court-admissible chain of custody.
**Red team (attack)**: Factor vendor key; forge/invalidate DUI test records — defense attorneys can challenge every conviction.
**Blue team (defense/recovery)**: Vendor key rotation; state-by-state re-certification.
**Impact**:
- $: Low millions
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=1, Exploitability=3, BlastRadius=1, Stealth=2, Recoverability=4.

### hid-osdp-seos
**Context**: HID SEOS credentials + OSDP v2 (physical-access control) use RSA-2048 (with ECC option) for credential PKI; hundreds of millions of credentials at enterprise/gov/military sites.
**Red team (attack)**: Factor HID/integrator CA; clone credentials for any building's access control — physical access to datacenters, labs, military bases.
**Blue team (defense/recovery)**: HID SEOS roadmap; credential reissuance ~3yr cycle.
**Impact**:
- $: Low billions
- Lives: Indirect (physical intrusion)
- Environment: None direct
- Geopolitical: Espionage capability
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=4, Recoverability=3.

### assa-abloy-hotel
**Context**: ASSA ABLOY/VingCard + dormakaba/Saflok hotel mobile-key + mobile-issuance uses RSA-2048 in authorization tokens; millions of hotel rooms (2024 Saflok/Dormakaba unsaflok CVE fresh memory).
**Red team (attack)**: Factor property CA; master-key any chain-wide lock set.
**Blue team (defense/recovery)**: OEM keyset update; door-by-door FW. Known to be slow (unsaflok still running).
**Impact**:
- $: Low billions
- Lives: Indirect (room intrusions)
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### axon-bodycam-evidence
**Context**: Axon Body-Worn Cameras + Evidence.com + Motorola WatchGuard sign video evidence with RSA-2048 for court chain-of-custody. US LE dominant.
**Red team (attack)**: Factor evidence-signing key; alter or forge bodycam evidence, compromise prosecutions.
**Blue team (defense/recovery)**: Axon controls SaaS key; rotation fast but historic evidence at risk.
**Impact**:
- $: Low billions (litigation + case challenges)
- Lives: Indirect (justice system)
- Environment: None direct
- Geopolitical: US LE credibility
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=3.

### voting-machine-signing
**Context**: ES&S, Dominion, Hart InterCivic voting systems sign ballot definitions + result cartridges with RSA-2048 under EAC/VVSG. ~175M US registered voters.
**Red team (attack)**: Factor vendor/county CA; forge result cartridges — but post-2020 risk-limiting audits + paper-ballot reconciliation mitigate substantially. Still: public trust in elections.
**Blue team (defense/recovery)**: EAC + CISA coordination; hand-count backstop.
**Impact**:
- $: Low billions
- Lives: Indirect (civic)
- Environment: None direct
- Geopolitical: US election legitimacy
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### gaming-gli33
**Context**: GLI-33 compliance for online gaming (sportsbook/casino) requires signed RNG outcomes + jackpot integrity under RSA-2048; DraftKings, FanDuel, BetMGM, EU Tipico.
**Red team (attack)**: Factor operator signing; forge jackpot events or manipulate bet-slip records.
**Blue team (defense/recovery)**: Gaming regulator re-cert; operator rotation.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### lottery-terminal
**Context**: IGT/Scientific Games/Intralot lottery terminals sign wager transactions + jackpot claims under RSA-2048; multi-state US + global.
**Red team (attack)**: Factor vendor/state CA; forge jackpot claims. Hot Lotto-style fraud reborn.
**Blue team (defense/recovery)**: State lottery commissions; vendor rotation.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### c2pa-content-credentials
**Context**: C2PA Content Credentials (Adobe, Microsoft, BBC, Sony, Canon, Nikon) sign media provenance with RSA-2048/ECDSA; post-2024 push against deepfakes.
**Red team (attack)**: Factor camera-OEM or C2PA CA; forge "authentic" provenance on deepfake media. Informational-integrity crisis.
**Blue team (defense/recovery)**: C2PA is designed for rotating trust lists; rollout still early so ecosystem can pivot.
**Impact**:
- $: Low billions
- Lives: Indirect (disinformation-incited)
- Environment: None direct
- Geopolitical: Information-war sovereignty
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=4.

### axis-onvif-video
**Context**: ONVIF Profile-T + Axis/Bosch/Hikvision/Dahua cameras use RSA-2048 for device certs + firmware signing; ~1B IP cameras globally.
**Red team (attack)**: Factor OEM CA; impersonate cameras in VMS, suppress evidence, or push malicious FW for botnets (Mirai-class but signed).
**Blue team (defense/recovery)**: ONVIF WG PQ; fleet FW update possible.
**Impact**:
- $: Low billions
- Lives: Indirect
- Environment: None direct
- Geopolitical: CN camera vendors (Hikvision/Dahua) banned in US/UK
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=3, Recoverability=3.

### digital-cinema-dci
**Context**: DCI Digital Cinema KDMs (Key Delivery Messages) use RSA-2048 to deliver CPL keys to cinema projectors (Christie, Barco, NEC); every commercial-release film.
**Red team (attack)**: Factor studio or projector CA; mint KDMs to decrypt pre-release content → mass piracy of tentpole releases.
**Blue team (defense/recovery)**: SMPTE + DCI updating specs; projector fleet update possible.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: Hollywood piracy
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### smpte-dcp-kdm
**Context**: Same scope as above; DCP packaging + KDM distribution via Deluxe, Technicolor.
**Ranking**: Same as dci.

### hdcp-2x-display
**Context**: HDCP 2.x uses RSA-3072 for LLC authentication; every 4K/8K HDMI-protected display, game console, streaming device.
**Red team (attack)**: Factor DCP LLC RSA root — arbitrary receiver cert generation, universal HDCP bypass. Mass piracy of premium streaming, Netflix/Disney+/Apple TV+ 4K content.
**Blue team (defense/recovery)**: DCP LLC cannot rotate silicon root easily; HDCP 3 PQ in discussion.
**Impact**:
- $: Tens of billions (streaming piracy)
- Lives: None direct
- Environment: None direct
- Geopolitical: Hollywood/streaming
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=4, Stealth=3, Recoverability=2.

### iata-bcbp-boarding
**Context**: IATA BCBP 3.0 boarding-pass signatures use RSA-2048 under IATA/airline CA; ~5B passengers/year.
**Red team (attack)**: Factor airline key; forge boarding passes evading TSA/airport security.
**Blue team (defense/recovery)**: IATA rotates, but airlines drag. TSA mitigates with additional factors.
**Impact**:
- $: Low billions
- Lives: Indirect (security circumvention)
- Environment: None direct
- Geopolitical: Global aviation
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### epassport-icao
**Context**: ICAO Doc 9303 ePassport Document Signer Certificates (CSCA/DSC) with RSA-2048/3072 for every passport issued post-2006. ~1B active passports.
**Red team (attack)**: Factor country CSCA (PKD-published); forge authentic ePassport chips for any identity, defeat border eMRTD verification. Espionage + mass immigration fraud.
**Blue team (defense/recovery)**: ICAO NTWG has PQ in 9303 v9 draft; CSCA rotation + re-issuance of 1B passports 10yr cycle.
**Impact**:
- $: Tens of billions
- Lives: Indirect (border-security, terrorism)
- Environment: None direct
- Geopolitical: Border-control sovereignty; state actors gain clandestine travel
**Ranking**: Criticality=4, Exploitability=3, BlastRadius=4, Stealth=5, Recoverability=2.

### icao-epassport-ds
**Context**: Companion example to above — document-signer issuance path.
**Ranking**: Same as above.

### eap-tls-wifi
**Context**: Enterprise Wi-Fi 802.1X EAP-TLS uses RSA-2048 server + client certs via FreeRADIUS/Cisco ISE/Aruba ClearPass; every enterprise + university.
**Red team (attack)**: Factor enterprise CA; impersonate Wi-Fi infrastructure or issue client certs — device onboarding and MitM.
**Blue team (defense/recovery)**: Enterprise CA rotation (ADCS dependency per above); client re-enroll.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=4, Recoverability=3.

### ipsec-ikev2-libreswan
**Context**: IPsec IKEv2 with RSA-signed auth via Libreswan/strongSwan/Cisco ASA/Fortinet/Palo Alto — every enterprise site-to-site VPN, mobile VPN, cloud VPN gateway.
**Red team (attack)**: Factor VPN CA; impersonate VPN peer, decrypt mass site-to-site traffic via active MitM.
**Blue team (defense/recovery)**: IPsec PQ RFCs (9242 hybrid, ML-KEM in progress); gateway fleet update multi-year.
**Impact**:
- $: Tens of billions (enterprise data)
- Lives: None direct
- Environment: None direct
- Geopolitical: VPN-based sovereign communications
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=5, Recoverability=3.

### strongswan
**Context**: strongSwan reference IPsec stack; identical threat surface to libreswan, plus used in many embedded/OT gateways.
**Ranking**: Same as ipsec-ikev2-libreswan.

### openvpn
**Context**: OpenVPN TLS handshake with RSA-2048/4096; ~50M users + thousands of enterprise installs.
**Red team (attack)**: Factor VPN CA; MitM or impersonate server, decrypt historical captures (no PFS in default configs pre-TLS 1.3).
**Blue team (defense/recovery)**: OpenVPN 2.7 + hybrid PQ in tree; admin reissue.
**Impact**:
- $: Low billions
- Lives: Indirect (activists, journalists)
- Environment: None direct
- Geopolitical: VPN-circumvention tooling
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=5, Recoverability=3.

### tor
**Context**: Tor uses RSA-1024 legacy relay ID keys (v2 — deprecated) + Ed25519 (v3) for onion services; current mainline is Ed25519 so RSA is legacy risk only.
**Red team (attack)**: Factor old v2 hidden-service keys → retroactive deanonymization of historic v2 services. v3 unaffected.
**Blue team (defense/recovery)**: v2 already disabled (2021); residual risk only.
**Impact**:
- $: None direct
- Lives: Direct (dissidents, sources deanonymized retroactively)
- Environment: None direct
- Geopolitical: Authoritarian-regime activism
**Ranking**: Criticality=2, Exploitability=4, BlastRadius=2, Stealth=5, Recoverability=5.

### apache-santuario
**Context**: Apache Santuario = the Java/C++ XMLDSig/XMLEnc library under nearly every SAML IdP/SP, government e-filing, and ebXML/HL7 CDA signing. RSA-2048 dominant.
**Red team (attack)**: XMLDSig + factored key = forge any signed XML (tax returns, customs declarations, SAML, ebXML invoices). Government document-integrity collapse.
**Blue team (defense/recovery)**: Library supports ML-DSA once signatures of XMLDSig 2.0 are ratified; integrator rollout slow.
**Impact**:
- $: Tens of billions (government revenue fraud)
- Lives: Indirect
- Environment: None direct
- Geopolitical: Every digital-government program affected
**Ranking**: Criticality=4, Exploitability=5, BlastRadius=4, Stealth=4, Recoverability=3.

### pdf-itext
**Context**: iText + Adobe PDF SDK sign PDFs (CAdES, PAdES, EUTL); legal/contract/government docs. RSA-2048/3072 dominant.
**Red team (attack)**: Factor signer CA; forge signed contracts, invoices, qualified electronic signatures (eIDAS). Legal-evidentiary chaos.
**Blue team (defense/recovery)**: EU QTSPs + eIDAS 2.0 PQ; Adobe/iText roadmap.
**Impact**:
- $: Tens of billions
- Lives: None direct
- Environment: None direct
- Geopolitical: EU digital-identity (EUDI Wallet) sovereignty
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=4, Recoverability=3.

### xmlsec1-xmldsig
**Context**: xmlsec1 (C library) underlies many OSS SAML/XMLDSig tools including Shibboleth, SimpleSAMLphp, eHerkenning (NL).
**Ranking**: Same severity as apache-santuario.

### ipaws-cap-alerts
**Context**: FEMA IPAWS / CAP 1.2 uses RSA-2048 for Wireless Emergency Alerts + EAS authority signing; all US emergency alerts.
**Red team (attack)**: Factor IPAWS signing CA; push forged EAS (e.g., ballistic missile — Hawaii 2018 but adversarial) to millions of phones/TVs.
**Blue team (defense/recovery)**: FEMA rotate; broadcaster/carrier update. Incident-level remediation.
**Impact**:
- $: Low billions
- Lives: Direct (panic casualties)
- Environment: None direct
- Geopolitical: US civil-defense credibility
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=3.

### weather-nws-nexrad
**Context**: NWS NEXRAD + NOAA data signing uses RSA-2048 for AWIPS/IRIS products; aviation/emergency depend on signed forecasts.
**Red team (attack)**: Factor NOAA CA; forge weather products — false tornado warnings, or worse, suppress real ones.
**Blue team (defense/recovery)**: NOAA PKI rotation; consumer update.
**Impact**:
- $: Low billions
- Lives: Direct (severe-weather deaths)
- Environment: None direct
- Geopolitical: NOAA credibility
**Ranking**: Criticality=3, Exploitability=3, BlastRadius=3, Stealth=3, Recoverability=4.

### mastodon-activitypub
**Context**: Mastodon/Fediverse HTTP-Signatures over RSA-2048; ~10M fediverse users + hundreds of instances.
**Red team (attack)**: Factor instance actor keys; impersonate moderators, inject bogus federated content; trust is per-instance so blast radius is contained.
**Blue team (defense/recovery)**: Admins rotate keys; users re-federate.
**Impact**:
- $: Negligible
- Lives: None direct
- Environment: None direct
- Geopolitical: Minor
**Ranking**: Criticality=2, Exploitability=5, BlastRadius=2, Stealth=2, Recoverability=5.

### libgcrypt
**Context**: libgcrypt is the GnuPG-foundation crypto library used by GnuPG, GNOME Keyring, libreswan, APT, many Linux daemons; RSA-2048/4096 heavily relied upon.
**Red team (attack)**: Library break = library-wide factoring oracle; every library client inherits the break. Not a crypto-key compromise per se but an ecosystem dependency signal.
**Blue team (defense/recovery)**: GnuPG team ships ML-KEM/ML-DSA; Linux distros roll out.
**Impact**:
- $: Tens of billions
- Lives: None direct
- Environment: None direct
- Geopolitical: Linux/OSS commons
**Ranking**: Criticality=3, Exploitability=5, BlastRadius=4, Stealth=3, Recoverability=3.

### libp2p-peer-id
**Context**: libp2p peer-id can be RSA-2048-derived; IPFS, Filecoin, Ethereum execution-layer light clients. Modern peers default Ed25519 but many historical peers RSA.
**Red team (attack)**: Factor peer-id RSA key; impersonate peer, Sybil attacks, content-provider spoofing on IPFS.
**Blue team (defense/recovery)**: libp2p moved Ed25519 default; migrate incentivized.
**Impact**:
- $: Low billions (web3 ecosystem)
- Lives: None direct
- Environment: None direct
- Geopolitical: Low
**Ranking**: Criticality=2, Exploitability=4, BlastRadius=2, Stealth=3, Recoverability=5.

### cisco-ios-pki
**Context**: Cisco IOS/IOS-XE/NX-OS internal PKI for certificate-based device auth, EEM, MACsec, SSH with RSA-2048 host keys; billions of enterprise/carrier ports.
**Red team (attack)**: Factor Cisco PKI CA + host keys; impersonate devices in routing trust, decrypt historic SSH/MACsec captures.
**Blue team (defense/recovery)**: IOS-XE 17+ supports ECDSA/Ed25519; fleet SSH-key rotation feasible but manual.
**Impact**:
- $: Tens of billions
- Lives: None direct
- Environment: None direct
- Geopolitical: US-Cisco infrastructure dominance
**Ranking**: Criticality=4, Exploitability=4, BlastRadius=4, Stealth=5, Recoverability=3.

### postgresql-ssl
**Context**: PostgreSQL TLS client/server auth with RSA-2048; ~millions of production databases including many banks, healthcare, SaaS.
**Red team (attack)**: Factor DB CA; impersonate DB server, MitM credentials/data.
**Blue team (defense/recovery)**: Postgres 17+ ECC default; rotate.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=3, Exploitability=4, BlastRadius=3, Stealth=4, Recoverability=4.

### ntp-autokey
**Context**: NTP Autokey (RFC 5906) used RSA-1024/2048; largely deprecated in favor of NTS. Residual deployments in OT.
**Red team (attack)**: Factor keys; time-shift victims triggering TOTP/HSTS/certificate-validation edge cases.
**Blue team (defense/recovery)**: NTS migration; Autokey sunset.
**Impact**:
- $: Negligible
- Lives: None direct
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=1, Exploitability=4, BlastRadius=1, Stealth=3, Recoverability=5.

### flexlm-license
**Context**: FlexNet/FlexLM license managers for EDA (Cadence, Synopsys, Ansys, MathWorks MATLAB), CAD (Autodesk) use RSA-2048 for license-file signing.
**Red team (attack)**: Factor publisher key; mint unlimited licenses → massive piracy wave across semiconductor/engineering.
**Blue team (defense/recovery)**: Flexera + publishers rotate keys; customer re-licensing. Commercial impact high.
**Impact**:
- $: Tens of billions (publisher revenue)
- Lives: None direct
- Environment: None direct
- Geopolitical: CN design ecosystem already under US EDA export controls — would benefit
**Ranking**: Criticality=2, Exploitability=4, BlastRadius=3, Stealth=3, Recoverability=3.

### asml-reticle-fab
**Context**: ASML EUV reticle-authentication + tool-recipe signing under RSA-2048 inside wafer-fab lithography; TSMC, Samsung, Intel; strategic-export-controlled.
**Red team (attack)**: Factor ASML signing key; push malicious tool recipes subtly degrading yield at fab scale; or unlock export-restricted capability on sanctioned-customer tools. State-level strategic payoff.
**Blue team (defense/recovery)**: ASML + customer re-cert slow; export-control wrappers are external.
**Impact**:
- $: Tens of billions (fab yield)
- Lives: None direct
- Environment: None direct
- Geopolitical: Sanctions-evasion + semiconductor-war geometry (NL-ASML, US, TW, KR, CN)
**Ranking**: Criticality=4, Exploitability=2, BlastRadius=4, Stealth=5, Recoverability=2.

### fuel-forecourt-epp
**Context**: EPS/Gilbarco/Wayne fuel forecourt protocols (IFSF, EPP) use RSA-2048 in card-reader key-loading + dispenser authentication; ~1M US dispensers + global.
**Red team (attack)**: Factor vendor key; clone dispenser creds, harvest skimmed card PANs, or override price/inventory.
**Blue team (defense/recovery)**: PCI + vendor rotation; dispenser visits.
**Impact**:
- $: Low billions
- Lives: None direct
- Environment: Fuel-theft enablement
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=3, Recoverability=4.

### racing-chip-timing
**Context**: RFID race-timing (MYLAPS, ChronoTrack) signs race results with RSA; triathlon/marathon/motorsport podium integrity.
**Red team (attack)**: Factor timing-vendor key; forge results, alter placings.
**Blue team (defense/recovery)**: Vendor rotation.
**Impact**:
- $: Negligible
- Lives: None
- Environment: None
- Geopolitical: None
**Ranking**: Criticality=1, Exploitability=3, BlastRadius=1, Stealth=2, Recoverability=5.

### themepark-ride-safety
**Context**: Disney/Universal/Six Flags PLC + ride-control FW signing under RSA-2048 per ASTM F24 + TÜV.
**Red team (attack)**: Factor OEM FW key; subtly alter brake-zone logic on coasters — ride fatality.
**Blue team (defense/recovery)**: TÜV/ASTM re-cert; ride downtime during FW rotation.
**Impact**:
- $: Low billions (park shutdown)
- Lives: Direct (ride fatalities)
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=3, Exploitability=2, BlastRadius=2, Stealth=3, Recoverability=3.

### triton-inference-mtls
**Context**: NVIDIA Triton Inference + cloud model-serving mTLS with RSA-2048; enterprise AI serving.
**Red team (attack)**: Factor model-serving CA; exfiltrate inputs/outputs or replace model with adversarial.
**Blue team (defense/recovery)**: Ops-team rotate.
**Impact**:
- $: Low billions
- Lives: Indirect (clinical-AI)
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=4, BlastRadius=2, Stealth=4, Recoverability=4.

### onnx-model-signing
**Context**: ONNX model artifact signing via RSA-2048 for ML supply-chain; Microsoft/Meta/Nvidia toolchains.
**Red team (attack)**: Factor publisher key; push backdoored models into enterprise inference — silent prediction manipulation.
**Blue team (defense/recovery)**: sigstore migration underway.
**Impact**:
- $: Low billions
- Lives: Indirect
- Environment: None direct
- Geopolitical: None
**Ranking**: Criticality=2, Exploitability=3, BlastRadius=2, Stealth=4, Recoverability=4.

### xmpp-s2s-tls
**Context**: XMPP s2s federation TLS with RSA-2048; enterprise messaging (Cisco Jabber, historical Google Talk), WhatsApp infra partially.
**Red team (attack)**: Factor server CA; decrypt federated traffic.
**Blue team (defense/recovery)**: Operators rotate; ecosystem small.
**Impact**:
- $: Negligible
- Lives: None direct
- Environment: None direct
- Geopolitical: Minor
**Ranking**: Criticality=1, Exploitability=4, BlastRadius=1, Stealth=4, Recoverability=5.


---

## Aggregate ranking

Composite = Criticality + Exploitability + BlastRadius + Stealth + (6 − Recoverability).
The Recoverability term is inverted so all five axes read "5 = worst" on the composite (since in the per-entry blocks I scored Recoverability as "5 = easy, 1 = impossible").  Max composite = 25.

### Tier S — civilization-level (composite 24–25)

| System | C | E | B | S | R | Composite |
|---|---|---|---|---|---|---|
| arm-trustzone-tfa | 5 | 5 | 5 | 5 | 1 | 25 |
| android-avb | 5 | 5 | 5 | 5 | 1 | 25 |
| hsm-firmware-signing | 5 | 5 | 5 | 5 | 1 | 25 |
| adcs-windows | 5 | 5 | 5 | 5 | 1 | 25 |
| autosar-ecu-hsm | 5 | 4 | 5 | 5 | 1 | 24 |
| iec62443-dtls-ot | 5 | 4 | 5 | 5 | 1 | 24 |
| siemens-s7-tia | 5 | 4 | 5 | 5 | 1 | 24 |
| iec62351-substation | 5 | 4 | 5 | 5 | 1 | 24 |
| ami-dlms-cosem | 5 | 4 | 5 | 4 | 1 | 23 |
| refinery-sis-iec61511 | 5 | 3 | 4 | 5 | 1 | 22 |

### Tier A — severe multi-sector (composite 21–23)

nuclear-iec61513 (23) · oilrig-bop-mux (23) · medical-device-fda (23) · avionics-arinc665 (23) · pipeline-api1164 (23) · shim-uefi (23) · authenticode-pe (23) · dnp3-scada (22) · swift-financial (22) · medtronic-cied (22) · submarine-cable-slte (22) · aerospace-ccsds (22) · piv-cac-smartcard (22) · iso15118-ev-charging (22) · evse-iso15118-pnc (22) · john-deere-agtech (21) · hydrodam-scada (21) · iaea-safeguards (21) · acars-cpdlc-datalink (21) · water-wima-scada (21) · emv-payment-cards (21) · sap-netweaver-sso (22) · ibm-icsf-mainframe (22) · windows-dpapi (23) · kubernetes-kubeadm (22) · aws-iot-device-certs (22) · esim-gsma (22) · pkcs11-softhsm (22) · tpm2-rsa-ek (22) · ipsec-ikev2-libreswan (20) · strongswan (20)

### Tier B — broad but less existential (composite 18–20)

apache-santuario (19) · pdf-itext (19) · xmlsec1-xmldsig (19) · cisco-ios-pki (19) · rpm-gpg-signing (22) · debian-apt-signing (22) · gnupg (22) · openssh-host-keys (20) · git-signed-commits (20) · openjdk-jarsigner (20) · uboot-secure-boot (22) · vestas-wind-turbine (20) · fanuc-robot (19) · railway-ertms (19) · us-ptc-railway (19) · cbtc-subway (19) · p25-otar-radio (18) · link16-mids (17) · gmdss-inmarsat (19) · iho-s63-ecdis (18) · epassport-icao (21) · icao-epassport-ds (21) · fido2-webauthn (20) · scep-mdm (21) · vault-pki (20) · nss-firefox (20) · acme-lets-encrypt (19) · rpki-routinator (20) · dnssec-bind9 (19) · kerberos-pkinit (20) · saml-ruby (19) · jwt-libjwt (19) · samba-netlogon (21) · opc-ua (18) · dicom-medical-imaging (18) · illumina-sequencer (18) · dscsa-pharma-serialization (18) · hl7-direct-fhir (17) · vaccine-coldchain-iot (17) · bloodbank-iso-udi (17) · hid-osdp-seos (18) · assa-abloy-hotel (16) · otis-elevator (18) · spacex-autonomous-fts (18) · ski-lift-doppelmayr (15) · themepark-ride-safety (16) · nvidia-gpu-attestation (19) · intel-sgx-signing (19) · intel-tdx-quote (19) · coco-attestation (17) · azure-attestation-jwt (22) · asml-reticle-fab (18) · hdcp-2x-display (19) · dvb-ci-pay-tv (14) · digital-cinema-dci (14) · smpte-dcp-kdm (14) · ipaws-cap-alerts (17) · weather-nws-nexrad (16) · atsc3-broadcast (16) · faa-remote-id (14) · iata-bcbp-boarding (17) · galileo-osnma (15) · digital-tachograph-eu (16) · eu-tachograph-dtco (16) · insurance-telematics-ubi (13) · komatsu-autonomous-mining (16) · axis-onvif-video (17) · cyrus-imap (18) · openldap-tls (18) · postfix-smtp-tls (19) · opendkim (18) · smime-email (19) · fix-cme-exchange (21) · pos-pci-pts (19) · hbci-fints-banking (16) · atm-xfs-firmware (20) · docsis-bpi-cable (15) · cbrs-sas-spectrum (15) · etc-tolling (14) · libgcrypt (20) · eap-tls-wifi (18) · postgresql-ssl (17) · rfc3161-tsa-timestamp (20) · gaming-gli33 (13) · voting-machine-signing (16) · docker-notary-tuf (19) · huggingface-commit-signing (18) · sigstore-model-signing (14) · openvpn (18) · gnupg-openpgp-card (19) · fuel-forecourt-epp (13) · thermofisher-massspec (13) · nuclear-iec62645 (15) · c2pa-content-credentials (15) · triton-inference-mtls (13) · onnx-model-signing (13) · ros2-sros2-dds (15) · osisoft-pi-historian (16) · flexlm-license (15) · axon-bodycam-evidence (13) · breathalyzer-dui (10) · lottery-terminal (13)

### Tier C — low or bounded (composite ≤13)

tor (8 — v3 unaffected; v2 legacy only) · ntp-autokey (8 — deprecated) · mastodon-activitypub (9) · xmpp-s2s-tls (8) · libp2p-peer-id (10) · racing-chip-timing (8)

---

## Top-5 prose synthesis

### 1. ARM Trusted Firmware-A + Android Verified Boot + HSM-vendor firmware signing + ADCS (Tier S)
These four are tied at composite 25 and share one pathology: **the public verification key is fused into ROM or baked into trust anchors that cannot be rotated without physical replacement**. ARM TF-A determines what every Cortex-A SoC will boot; AVB gates every Android userspace; HSM firmware roots define what the enterprise crypto fabric will load; ADCS is the default enterprise PKI inside every Windows domain. A polynomial factoring algorithm is not just a key-theft event but a *silicon-refresh and PKI-rebuild event* on a multi-year, multi-trillion-dollar timescale. AWS Graviton fleets, every Pixel/Samsung/Xiaomi user, every bank with a Thales/Entrust/Utimaco HSM, and every AD-joined enterprise are forced into a simultaneous hardware-refresh cycle. Adversary doesn't need insider access — the public keys are literally published in chip datasheets, device teardowns, Microsoft's TechNet, and HSM vendor Firmware Update Bulletins. Stealth is maximal because the break forges valid signatures indistinguishable from legitimate ones; detection requires out-of-band attestation which itself relies on the broken crypto.

### 2. AUTOSAR ECU HSM + IEC 62443 OT + Siemens S7 + IEC 62351 substation (Tier S, 24)
All four are the **cryptographic gate on safety-affecting OT**: ~100M new vehicles per year with signed ECU firmware, process-plant DCS/SIS signatures at every Fortune 500 industrial site, S7-1500 PLCs controlling everything from pharma-line sterilization to municipal water, and IEC 61850 GOOSE/SV messages trip-coordinating every transmission substation. The red-team payoff is not fraud but **controllable unsafe behavior** at civilian-casualty scale: Stuxnet generalized to every Siemens PLC, brake/steering manipulation across a manufacturer's fleet, Ukraine-grid-attack 2015 across every transmission grid. Recoverability=1 because device firmware ROM keys are unrotatable and IEC/ISO safety re-certification cycles measured in years apply; a polynomial factoring announcement triggers *regulatory-shutdown* conditions (BSEE, NRC, PHMSA, FMCSA, CAA-EASA) before replacement silicon exists. This is the cluster most likely to produce *kinetic mass-casualty* events if not preempted.

### 3. Nuclear I&C (IEC 61513), oil-rig BOP/MUX, medical-device FDA, airframe ARINC 665, pipeline API 1164 (Tier A, 23)
The "strategic safety-critical signing" group: each combines **regulator-approved cryptographic assurance as license basis** with **mass-casualty consequences on failure**. Red-team attack is harder (Exploitability=3: it requires the factored key to be plausibly distributable to the compromised facility, and regulatory airgaps add friction), but the impact is asymmetric — a single successful attack is Macondo, Bhopal, Lion Air, Northstar 1, or a regulator-forced fleet shutdown. Each sector has already begun PQ roadmap scoping (BSEE 30 CFR 250.734, FAA DO-326A/356A, FDA 524B, PHMSA SD-02C, NRC RG 1.152 Rev 4) but **license-basis cryptographic changes are measured in years per plant / type / field**. The polynomial-factoring scenario collapses all these timelines into a simultaneous emergency; the realistic defensive posture is *operating restriction + manual reverification*, which in aggregate is measured in tens of billions of dollars of lost operating days.

### 4. Microsoft Authenticode + Shim UEFI + Windows DPAPI (Tier A, 23)
The **Windows endpoint chain of trust**: driver-loading, Secure Boot, and stored-credential protection. A polynomial factoring algorithm yields kernel-level persistence (Authenticode), pre-OS persistence (shim), and retroactive decryption of every BitLocker recovery key, browser password, and DPAPI-protected credential ever sealed against a factored DPAPI backup key. Stealth=5 because Microsoft's telemetry itself trusts the broken crypto; Exploitability=5 because the verification roots are on every Windows box by design. Microsoft has a PQ roadmap (SymCrypt ML-DSA/ML-KEM) but legacy-signed driver ecosystem inertia makes revocation a CRL-distribution problem at planetary scale. This is the practical "every Windows machine is now hostile" scenario.

### 5. SWIFT + IBM ICSF + EMV + SAP NetWeaver + ADCS (Tier A, 21-23, financial-system cluster)
The **financial-system-of-record cluster**: SWIFT messages ~$150T/year; IBM Crypto Express wraps 80% of global-bank core keys; EMV mints ~5B payment cards; SAP is the system of record for most Fortune-500 revenue and most G20 ministries. A polynomial factoring algorithm does not collapse fraud-detection (operational controls persist), but it does collapse the **authenticity-of-record** property on which the entire interbank/ledger/invoicing/payroll fabric is premised. Blue-team recovery is a rail-by-rail, HSM-by-HSM, card-by-card reissuance measured in tens of billions of dollars of industry spend and years of elevated fraud. Geopolitically, sanctioned actors (RU/IR/DPRK) and peer-competitor blocs (CN) are the disproportionate beneficiaries because the incumbent US/EU-dominated rails are the ones with the most exposed RSA dependency.

---

## Cross-cutting observations

1. **Recoverability, not Exploitability, is the dominant axis.** Many systems have Exploitability=5 (public key, trivially broken) but Recoverability=4-5 (fix is a config rotation). The civilization-scale risks concentrate where Recoverability=1 — ROM fuses, regulator-approved license basis, physical replacement of implanted devices, multi-trillion-dollar HSM refresh.

2. **"Classical-only" narrows the blast radius from the Shor scenario but does not make it small.** Because this threat model preserves ECDSA/Ed25519/ECDH, systems that had already migrated (modern TLS with ECDHE, mTLS with Ed25519, FIDO2 attestation in per-credential keys, PQ-ready mesh) survive. The exposure is overwhelmingly concentrated in *administrative signing* paths: regulator-mandated signed artefacts, firmware chains of trust, enterprise PKI roots, and silicon-fused device-identity roots — paths that moved slowest because of compliance gravity.

3. **Harvest-now-decrypt-now (HNDN) is not the primary concern** for this threat model. Because ECDH is intact in modern handshakes, most modern TLS traffic is confidentiality-forward-secure against this adversary. The painful HNDN cases are the ones still using RSA key-transport (TLS 1.2 non-ECDHE, legacy S/MIME, historical OpenVPN, EMV offline auth, static-RSA smartcard readers) and the forgery-of-history cases (Tor v2 descriptors, evidence chains with historic RSA timestamps, archived RSA-signed legal documents).

4. **The worst-case attacker is not the ransomware crew.** The attacker-value gradient runs: ransomware (pick off ATMs, lottery, hotel locks) → organized fraud (SWIFT, EMV, tax/customs e-filing) → state SIGINT (ePassport, PIV/CAC, PKI roots, VPN CAs) → strategic state actor (safety-I&C, BOP, SIS, avionics, grid). Tier-S/A systems are strategic-state-actor-grade targets, consistent with the observed investment in long-term cryptanalysis by the same actors.

5. **PQ migration completion rate is the single best predictor of recovery posture.** Every system with PQ-capable silicon already shipping (AWS Nitro, Azure MAA, iOS Secure Enclave 2024+, Pixel 9+, Chrome TLS hybrid, Signal PQXDH) degrades gracefully. Every system on ROM-fused RSA silicon in long-life infrastructure (older TPMs, EV/auto ECUs, industrial PLCs with 20-year life, submarine-cable SLTE, legacy BOP pods) *cannot* degrade gracefully; polynomial-factoring day is replacement-cycle day.
