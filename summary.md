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
