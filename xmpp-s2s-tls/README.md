# xmpp-s2s-tls — RSA in XMPP S2S federation TLS (Jabber, Cisco Jabber, German TI Messenger)

**Repository:** ejabberd (processone/ejabberd), Prosody (prosody.im)  
**Industry:** Federated messaging — open XMPP network, enterprise IM, German healthcare  
**Algorithm:** RSA-2048 (XMPP S2S server certificate; SASL EXTERNAL identity via TLS cert)  
**PQC migration plan:** None — ejabberd and Prosody use OpenSSL/GnuTLS for TLS; no PQC TLS in stable releases; XMPP Standards Foundation (XSF) has no active XEP for PQC

## What it does

XMPP (Jabber) is the federated instant messaging protocol. Server-to-server (S2S) federation
on port 5269 uses TLS with RSA-2048 certificates. XEP-0178 (SASL EXTERNAL) authenticates
XMPP servers to each other via TLS certificate identity — the domain in the certificate CN/SAN
is the XMPP domain. Every message sent between different XMPP domains goes over S2S TLS.

Deployed in:
- Public XMPP federation (jabber.org, xmpp.jp, ~1000 federated servers)
- Cisco Unified Communications Manager / Cisco Jabber — enterprise IM for Fortune 500
- German TI Messenger (Telematikinfrastruktur healthcare messaging, Gematik-mandated)
- BwMessenger (Bundeswehr, German military internal messaging)
- WhatsApp protocol is XMPP-derived (uses ejabberd internally at scale)

The S2S TLS certificate is on an openly accessible port — S2S federation requires port 5269
to accept connections from any XMPP server worldwide. The RSA-2048 public key is available
from any TLS handshake to port 5269, no credentials required. This is a design requirement
of federated XMPP: the port must be open.

## Why it's stuck

- ejabberd and Prosody use the system TLS library (OpenSSL or GnuTLS). PQC in those
  libraries is experimental. No XMPP server is shipping PQC TLS in a stable release.
- XEP-0178 defines SASL EXTERNAL via TLS cert. The cert is X.509. There is no XEP
  for PQC-based S2S authentication, and no active work item in XSF to create one.
- The German TI Messenger uses Gematik-issued certificates from Gematik's PKI.
  Gematik has not announced PQC plans for TI Messenger certificates.
- Cisco Jabber / CUCM RSA certificates are managed by enterprise PKI (usually ADCS).
  PQC in ADCS requires Windows Server update + CA template update + cert re-issuance.

## impact

XMPP S2S port 5269 is literally required to be open to the internet for federation.
the RSA cert is on an open port. anyone can grab it.

- connect to port 5269 of any federated XMPP server. do a TLS handshake. get the
  RSA-2048 public key. no auth. this is how federation is supposed to work.
  factor the key. derive the private key. impersonate the server to all its XMPP peers.
  receive messages intended for users on that server.
- for the German TI Messenger: these are healthcare communications — patient referrals,
  lab results, emergency coordination between hospitals and ambulance services. the TI PKI
  is Gematik-issued RSA-2048. factor the hospital server's cert, intercept healthcare
  messages for all patients at that institution.
- for Cisco Jabber enterprise: XMPP messages between Cisco Jabber users include M&A
  discussions, legal privileged communication, HR discussions, financial information.
  the CUCM S2S cert is RSA-2048 from the enterprise CA. impersonating the CUCM server
  gives you all enterprise IM traffic.
- SASL EXTERNAL forgery: an attacker who factors any domain's S2S RSA cert can authenticate
  as that domain to every federated server. send messages as if from users on that domain.
  a message appearing to come from @bundeswehr.de or @gematik.de or @bankofamerica.com,
  signed with the correct server RSA cert, will pass federation authentication.
- BwMessenger (Bundeswehr): German military internal messaging. the S2S cert is an RSA-2048
  cert within the German government PKI. same attack chain.

## Code

`xmpp_s2s_rsa.py` — `xmpp_s2s_connect()` (S2S TLS with RSA-2048 client cert on port 5269),
`xmpp_sasl_external_auth()` (XEP-0178 SASL EXTERNAL domain auth via cert), `get_xmpp_server_cert()`
(grab RSA-2048 S2S cert from open port 5269 without credentials). TI Messenger / Gematik
healthcare context and Cisco CUCM enterprise deployment in comments.
