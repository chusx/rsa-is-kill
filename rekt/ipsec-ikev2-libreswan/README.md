# ipsec-ikev2-libreswan — RSA authentication in VPN tunnels

**Software:** Libreswan (libreswan/libreswan) — dominant Linux IKEv2/IPsec 
**Industry:** Enterprise VPN, government classified networks, cloud VPN gateways 
**Algorithm:** RSA-2048 to RSA-4096 (rsasigkey default: random 3072-4096) 

## What it does

IKEv2 (RFC 7296) authenticates VPN peers via the AUTH payload — each side
signs a value derived from the IKE_INIT exchange with its RSA private key.
This is separate from the Diffie-Hellman key exchange: even if the DH is
unaffected, broken RSA authentication means an attacker can impersonate any
VPN endpoint.

`rsasigkey` generates raw RSA keys stored in `ipsec.secrets`. Default key
size: randomly chosen between 3072 and 4096 bits (intentionally non-uniform).
The RSA public key is published in DNS as an RFC 3110 IPSECKEY record for
opportunistic IPsec.

## Why it's stuck

**RFC 8784** (2020) adds a Post-quantum Preshared Key mechanism to IKEv2 for
the key exchange — but explicitly states:

> "This document does not provide security against a factoring break for the IKE SA
> authentication." — RFC 8784 §1

The IKEv2 authentication problem requires:
1. New RFC with non-RSA signature algorithm IDs for IKE_AUTH
2. IKEv2 implementations (Libreswan, strongSwan, Windows IKEv2) to support them
3. Certificate infrastructure with non-RSA-signed X.509 certs
4. Coordinated upgrade of both VPN endpoints

Government classified networks (CNSA 2.0, NSA/CNSS Policy 15) mandate non-RSA
for new systems after 2025, but IKEv2 authentication has no standardized
non-RSA mechanism to satisfy this mandate.

## impact

IKEv2 authentication proves who you're talking to. forge the RSA identity of a VPN endpoint and you can impersonate it to everyone who connects, transparently.

- MitM classified government traffic: impersonate the far end of an IPsec tunnel used for classified network interconnects (SIPRNet/JWICS gateways use IPsec). intercept and modify everything in transit
- forge a corporate VPN server's RSA identity and redirect all VPN clients to your gateway. mass credential harvest, and clients see a valid cert so nothing looks wrong at all
- many ISPs and CDNs run BGP over IPsec tunnels. impersonate the IPsec peer, hijack the BGP session, start rerouting internet traffic
- RFC 8784 non-RSA PPK protects the session key but explicitly does not fix authentication. an attacker can still impersonate a legitimate peer even with PPK deployed. the RFC says this itself
## Code

`rsasigkey_ikev2.c` — `RSA_pubkey_content_to_ipseckey()` (RFC 3110 DNS format
for RSA public key), `MIN_KEYBIT = 2192` constant, and the RFC 8784 limitation
note showing authentication remains RSA even with non-RSA key exchange.
