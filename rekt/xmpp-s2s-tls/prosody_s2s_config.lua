-- prosody_s2s_config.lua
--
-- Prosody's main config snippet exercising the XMPP server-to-server
-- (S2S) TLS + Dialback-with-X.509 code paths. Maps to the RSA
-- primitive invocations in `xmpp_s2s_rsa.py` (Python reference port
-- of the same crypto flow used by Prosody, ejabberd, MongooseIM,
-- Openfire).
--
-- Deployments: XMPP federation is still alive at scale in:
--   - jabber.ccc.de, jabber.org, matrix.org (XMPP legacy bridge)
--   - Cisco Jabber on-prem (~millions of enterprise seats)
--   - WhatsApp internal infra historically derived from ejabberd
--     (XMPP-over-TLS for server-to-server gateway tiers)
--   - Every government/municipal chat federation stood up under
--     "secure government messaging" initiatives in DE, FR, NL
--   - XEP-0220 Server Dialback + RFC 6120 TLS between independent
--     operator domains

-- ---------------- Global ----------------
admins = { "ops@chat.example.com" }

plugin_paths = { "/usr/local/lib/prosody/modules" }

modules_enabled = {
    "roster", "saslauth", "tls", "dialback", "disco",
    "private", "vcard", "ping", "register",
    "carbons", "pep", "mam",
    "s2s_auth_certs",      -- require valid cert on every S2S
    "s2s_whitelist",
}

-- ---------------- Core TLS / RSA key material ----------------
-- Prosody's s2s handshake terminates mutual TLS when the remote
-- supports it (RFC 6120 §13.3).  Chain → a publicly-trusted RSA-
-- 2048+ cert (Let's Encrypt, Sectigo, DigiCert) or to an XMPP-
-- federation-specific CA in government deployments.
ssl = {
    certificate = "/etc/prosody/certs/chat.example.com.crt";
    key         = "/etc/prosody/certs/chat.example.com.key";
    cafile      = "/etc/ssl/certs/ca-certificates.crt";
    protocol    = "tlsv1_2+";
    options     = { "no_sslv2"; "no_sslv3"; "no_compression"; "cipher_server_preference"; };
    ciphers     = "HIGH:!aNULL:!MD5:!3DES";
}

-- ---------------- c2s (client-to-server) ----------------
-- End-users authenticate PLAIN-over-TLS (SCRAM-SHA-256 when clients
-- support it).  The server's RSA cert is what the client pins.
c2s_require_encryption = true
c2s_tls_require_server_name = true
authentication = "internal_hashed"

-- ---------------- s2s (server-to-server federation) ----------------
-- Either SASL-EXTERNAL with mutual X.509 (preferred) or Server
-- Dialback.  Dialback uses a shared secret, but the connection
-- itself is still encrypted with RSA-based TLS, so a CA break is
-- still an S2S compromise vector.
s2s_require_encryption = true
s2s_secure_auth        = true       -- require successful cert chain
s2s_insecure_domains   = { }        -- no insecure peers

-- Per-peer auth policy
Component "chat.example.com" "muc"
    modules_enabled = { "muc_mam"; "vcard_muc"; }
    restrict_room_creation = "local"

-- ---------------- Cert renewal hook ----------------
-- prosodyctl cert import <path>; prosodyctl reload -- no process
-- restart; live-reload on RSA cert rotation (cert-manager, acme.sh,
-- certbot).
prosody_reload_on_cert_change = true

-- ---------------- Component / gateway TLS ----------------
-- External components (transport gateways, legacy XMPP-to-IRC
-- bridges) authenticate via TLS client cert + SASL EXTERNAL.
Component "mix.example.com" "mix"
Component "pubsub.example.com" "pubsub"


-- ---------------- Notes for operators ----------------
--
-- * `s2s_auth_certs` module walks the peer's presented X.509 chain
--   against /etc/ssl/certs during every inbound S2S bring-up; if it
--   fails the chain validation, S2S falls back to dialback which
--   requires both endpoints to have DNS-verifiable TXT secrets.
-- * `mod_mam` (Message Archive Management) stores chat history on
--   disk encrypted-at-rest using the cluster's own RSA key pair
--   for per-archive master-key wrap (database-backend dependent).
-- * Every federated exchange with Cisco WebEx XMPP gateway requires
--   cert-pinned RSA mutual auth: WebEx pins Cisco's intermediate.

--
-- ---------------- Breakage ----------------
--
-- A factoring attack against:
--
-- - **A publicly-trusted web CA (Let's Encrypt, Sectigo, DigiCert)**:
--   attacker mints a chat.example.com cert and MITM's S2S
--   federation globally. Every private conversation between two
--   federated domains becomes observable to whichever on-path
--   attacker holds a forged cert for either side.
--
-- - **The enterprise chat-federation root** (government / corporate
--   closed federation): attacker joins as a rogue server, receives
--   every message routed by any peer server that trusts that root.
--   In government deployments where classified-but-unclassified
--   chat runs over federated XMPP, this is a confidentiality
--   compromise on par with a mail-server-root break.
--
-- - **Per-domain keypair**: limited to that domain's S2S legs; but
--   message archives under `mod_mam` remain decryptable for the
--   retention window (years in regulated sectors).
--
-- XMPP dialback's DNS-TXT proof is an RSA-independent fallback
-- only if the remote end explicitly disables `s2s_secure_auth`,
-- which most 2020s deployments do not.
