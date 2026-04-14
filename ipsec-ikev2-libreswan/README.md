# ipsec-ikev2-libreswan — RSA authentication in VPN tunnels

**Software:** Libreswan (libreswan/libreswan) — dominant Linux IKEv2/IPsec  
**Industry:** Enterprise VPN, government classified networks, cloud VPN gateways  
**Algorithm:** RSA-2048 to RSA-4096 (rsasigkey default: random 3072-4096)  
**PQC migration plan:** None — RFC 7427 (IKEv2 sig auth) has no PQC auth algorithm IDs; RFC 8784 only fixes KEM, not authentication

## What it does

IKEv2 (RFC 7296) authenticates VPN peers via the AUTH payload — each side
signs a value derived from the IKE_INIT exchange with its RSA private key.
This is separate from the Diffie-Hellman key exchange: even if the DH is
PQC-safe, broken RSA authentication means an attacker can impersonate any
VPN endpoint.

`rsasigkey` generates raw RSA keys stored in `ipsec.secrets`. Default key
size: randomly chosen between 3072 and 4096 bits (intentionally non-uniform).
The RSA public key is published in DNS as an RFC 3110 IPSECKEY record for
opportunistic IPsec.

## Why it's stuck

**RFC 8784** (2020) adds a Post-Quantum Preshared Key mechanism to IKEv2 for
the key exchange — but explicitly states:

> "This document does not provide post-quantum security for the IKE SA
>  authentication." — RFC 8784 §1

The IKEv2 authentication problem requires:
1. New RFC with PQC signature algorithm IDs for IKE_AUTH
2. IKEv2 implementations (Libreswan, strongSwan, Windows IKEv2) to support them
3. Certificate infrastructure with PQC-signed X.509 certs
4. Coordinated upgrade of both VPN endpoints

Government classified networks (CNSA 2.0, NSA/CNSS Policy 15) mandate PQC
for new systems after 2025, but IKEv2 authentication has no standardized
PQC mechanism to satisfy this mandate.

## why is this hella bad

IKEv2 authentication proves *who you're talking to*. Forging RSA auth keys means:

- **MitM classified government traffic**: VPN peer impersonation → intercept and modify traffic on IPsec tunnels used for classified network interconnects (SIPRNet, JWICS gateway connections use IPsec)
- **Corporate VPN impersonation**: forge the VPN server's RSA identity → redirect all corporate VPN clients to an attacker-controlled gateway → mass credential harvest
- **BGP peering sessions over IPsec**: many ISPs and CDNs run BGP over IPsec tunnels. Forge the IPsec peer → hijack BGP sessions → route internet traffic
- RFC 8784 (PQC PPK) protects the *session key* but not *who you're authenticating to* — an attacker can still impersonate a legitimate peer even with PPK deployed, because authentication remains RSA

## Code

`rsasigkey_ikev2.c` — `RSA_pubkey_content_to_ipseckey()` (RFC 3110 DNS format
for RSA public key), `MIN_KEYBIT = 2192` constant, and the RFC 8784 limitation
note showing authentication remains RSA even with PQC key exchange.
