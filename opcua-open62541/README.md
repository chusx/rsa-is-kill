# opcua-open62541 — RSA in industrial control systems

**Software:** open62541 (open62541/open62541) — reference OPC-UA implementation  
**Industry:** Industrial automation, SCADA, manufacturing, energy, water treatment  
**Algorithm:** RSA-PKCS1-v1.5 + SHA-1 (Basic128Rsa15), RSA-OAEP + SHA-256 (Basic256Sha256)  
**PQC migration plan:** None — no PQC security policy in OPC-UA specification Part 7

## What it does

OPC-UA (IEC 62541) is the dominant machine-to-machine communication protocol
for industrial control systems. Every major PLC, SCADA system, historian, and
industrial IoT gateway supports it. The security policies all use RSA:

| Policy | Signature | Encryption |
|--------|-----------|------------|
| Basic128Rsa15 | RSA-PKCS1-v1.5 + SHA-1 | RSA-PKCS1-v1.5 (128-bit AES session key) |
| Basic256 | RSA-PKCS1-v1.5 + SHA-1 | RSA-OAEP + SHA-1 |
| Basic256Sha256 | RSA-PKCS1-v1.5 + SHA-256 | RSA-OAEP + SHA-256 |
| Aes128Sha256RsaOaep | RSA-OAEP + SHA-256 | RSA-OAEP + SHA-256 |
| Aes256Sha256RsaPss | RSA-PSS + SHA-256 | RSA-OAEP + SHA-256 |

All five policies are RSA. The ECC policy (EccNistP256) was added late and
has minimal deployment. No PQC policy exists or is planned in the OPC-UA spec.

## Why it's stuck

Industrial control systems have 20-40 year lifecycles. PLCs, DCS units, and
field devices deployed today will be running in 2045. Firmware updates are
rare; cryptographic agility is not an ICS design goal. The OPC-UA Foundation
would need to publish a new Part 7 revision with a PQC policy URI, and every
vendor would need to implement it. The installed base cannot be updated.

A CRQC targeting industrial infrastructure could:
1. Forge PLC command authentication (open valves, trip breakers, stop motors)
2. Decrypt session traffic from historian/SCADA to field devices
3. Impersonate engineering workstations during configuration

## impact

OPC-UA Basic128Rsa15 is still deployed on real industrial control systems. it uses RSA-PKCS1-v1.5, which is classically weak too (Bleichenbacher), and completely dead against a CRQC.

- forge OPC-UA session authentication against a PLC or SCADA server and write setpoints, modify process parameters, issue control commands to industrial equipment
- Basic256Sha256 uses RSA-2048 OAEP, which is better classically, but Shor's algorithm still kills it. session key exchange is RSA-wrapped
- industrial systems run for 10-20 years. a PLC set up in 2020 with Basic128Rsa15 will still be running in 2035 and there's no hot-patching an ICS for crypto agility
- certificate management in OT environments is famously bad. self-signed RSA certs with 10-year validity are standard. all those public keys are just sitting there
## Code

`securitypolicy_basic128rsa15.c` — Basic128Rsa15 policy implementation showing
`UA_OpenSSL_RSA_PKCS1_V15_SHA1_Verify`, `UA_Openssl_RSA_PKCS1_V15_Decrypt`,
and the policy URI `http://www.w3.org/2001/04/xmlenc#rsa-1_5`.
