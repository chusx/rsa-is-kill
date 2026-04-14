# strongSwan — RSA X.509 Certificate Verification (IKEv2)

**Source:** https://github.com/strongswan/strongswan  
**File:** `src/libstrongswan/plugins/x509/x509_cert.c`  
**License:** GPLv2

## what it does

strongSwan is the dominant open-source IPsec/IKEv2 VPN implementation on Linux. `issued_by()` verifies that a certificate was signed by a given CA — this is called during IKEv2 AUTH exchange when a VPN peer presents its certificate for authentication.

## impact

strongSwan is an IPsec implementation used for site-to-site VPNs, remote access, and as the IKE daemon on a lot of embedded systems and routers.

- forge RSA authentication in IKE_AUTH and impersonate any VPN endpoint. MitM site-to-site tunnels between offices, data centers, or cloud VPCs
- industrial control systems use strongSwan for IEC 62443 secure remote access. forge the IPsec peer authentication and you're inside the OT network
- certificate-based IKEv2 is the recommended strong auth configuration. forging the certificate forges the auth. there's no second factor in the protocol
- RFC 8784 PPK gives PQC key exchange but authentication is still RSA certificates. "quantum-resistant VPN" deployments using only PPK are misleading if authentication isn't also upgraded
## migration status

strongSwan has experimental PQC support via the `oqs` plugin (liboqs). Not available in distro packages, not standardized in IKEv2, not deployed in practice.
