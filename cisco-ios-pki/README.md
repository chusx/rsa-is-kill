# cisco-ios-pki — RSA in Cisco IOS PKI (enterprise routers, campus switches, VPN)

**Repository:** Cisco IOS/IOS-XE (proprietary); cisco.com documentation  
**Industry:** Enterprise networking — campus, WAN, data center, SP; also government and DoD networks  
**Algorithm:** RSA-2048 (default for all crypto pki, SSH, HTTPS management); RSA-4096 optional  
**PQC migration plan:** None — Cisco IOS-XE 17.x has no PQC key type in `crypto key generate`; IETF PQC-in-IKEv2 drafts not implemented; no Cisco shipping IOS-XE with ML-DSA or ML-KEM

## What it does

Cisco IOS generates RSA keypairs for every managed function: HTTPS management interface,
SSH host keys, IKEv2 certificate-based VPN authentication, and SCEP certificate enrollment
to the enterprise CA. `crypto key generate rsa modulus 2048` is the default on every
router and switch deployed since the early 2000s.

The public key is visible from multiple network-reachable attack surfaces:
- TLS ServerHello on port 443/8443 (HTTPS/RESTCONF/NETCONF management)
- SSH host key exchange on port 22
- IKEv2 certificate exchange on UDP/500 (VPN endpoints)

In enterprise networks, every Cisco device (ISR router, Catalyst switch, ASR) has an
RSA-2048 certificate issued by SCEP from the enterprise CA (usually Microsoft ADCS).
Cisco DNA Center automates SCEP enrollment at scale — large enterprises have thousands
of devices each with an RSA-2048 device identity certificate.

## Why it's stuck

- `crypto key generate` in IOS-XE supports only `rsa` and `ec` key types. There is no
  `ml-dsa` or PQC equivalent. Cisco would need a software update for every IOS-XE device.
- Cisco device firmware updates in enterprise environments go through change management,
  testing, and maintenance windows. A network-wide IOS-XE update to support PQC keys
  is a multi-year project for large enterprises.
- IKEv2 PQC drafts (draft-ietf-ipsecme-ikev2-pqc-*) are still in IETF development.
  No stable RFC exists. Without an RFC, Cisco won't ship a production implementation.
- The management TLS certificate is often the same RSA key used for everything. Rotating
  it requires touching every device, which for a large network is a significant operation.

## impact

cisco routers are the management plane for enterprise and government networks. the RSA key
is how you know you're talking to the router and not an impersonator.

- pull the RSA-2048 public key from any router's HTTPS management interface (it's in the
  TLS certificate, sent in the clear during TLS handshake). factor it. derive the private
  key. now you can impersonate the router to its NMS (Cisco Prime, DNA Center, SolarWinds).
  the NMS sends configuration changes; you ACK them and do nothing. or you record them and
  replay them modified.
- SSH MitM: factor the SSH host key RSA-2048. position between the admin and the router.
  the SSH host fingerprint matches. the admin types their password; you have it. then you
  relay commands and intercept responses. the admin thinks they're on the real router.
- IKEv2 VPN: factor the device certificate RSA-2048. forge the IKEv2 authentication.
  establish an unauthorized site-to-site VPN. you're inside the MPLS network or SD-WAN
  fabric as a legitimate site. traffic routes through you.
- for DoD/government networks: DoD mandates PKI (CAC/PIV) everywhere, including for
  network device authentication. the device certificates are RSA-2048. factoring them
  breaks device authentication across the entire network management plane.

## Code

`cisco_ios_rsa.txt` — IOS CLI reference showing `crypto key generate rsa modulus 2048`,
`crypto pki trustpoint` SCEP enrollment, `show crypto key mypubkey rsa` (public key output),
`ip ssh rsa keypair-name` (SSH host key), and the absence of PQC key types in `crypto key generate ?`.
Attack surface and Cisco DNA Center deployment scale in comments.
