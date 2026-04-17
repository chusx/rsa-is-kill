# OpenVPN — RSA TLS Authentication

**Source:** https://github.com/OpenVPN/openvpn 
**File:** `src/openvpn/ssl_openssl.c` 
**License:** GPLv2

## what it does

OpenVPN uses RSA certificates for mutual TLS authentication between client and server. The code here implements a custom `RSA_METHOD` that hooks into OpenSSL's signing path, allowing OpenVPN to delegate private key operations to an external process (hardware token, management daemon).

## impact

OpenVPN uses X.509 RSA certificates to authenticate peers. the server cert, client cert, and CA cert chain are all RSA in default configurations.

- forge the server certificate and MitM every client connection. clients see a valid certificate, the TLS handshake succeeds, traffic flows through the attacker transparently
- forge a client certificate and connect as any VPN user without credentials
- OpenVPN is widely deployed for corporate remote access. MitM the VPN and you're inside the network with full visibility of everything
- TLS-Auth and TLS-Crypt add a pre-shared key layer but don't fix RSA certificate authentication. the PSK protects against unauthenticated TLS connections but doesn't help if you can forge the RSA cert
