# hsm-firmware-signing — RSA in HSM firmware authentication (Thales Luna, Utimaco, nShield)

**Repository:** Thales Luna, Utimaco SecurityServer, Entrust nShield (proprietary) 
**Industry:** Root CA HSMs, payment HSMs, enterprise key management — the hardware everyone else relies on 
**Algorithm:** RSA-2048 (firmware signing cert burned into HSM ROM at manufacture) 

## What it does

Hardware Security Modules are the hardware that protects cryptographic keys — Root CA private
keys, payment PIN keys, enterprise master keys. The HSM is supposed to be the last line of
defense: even if software is compromised, the hardware security boundary means the key never
leaves the HSM in plaintext.

The firmware that runs inside the HSM's secure processor is authenticated with RSA-2048.
The vendor's root CA cert is burned into ROM at manufacture. Every firmware update image
carries an RSA-2048 signature that the HSM bootloader verifies before loading. If the
signature fails, the firmware update is rejected.

This is the only technical control preventing an attacker from running arbitrary code inside
the HSM's hardware security boundary. The tamper sensors, zeroization logic, and secure enclave
are all irrelevant once you control the firmware.

Vendors and deployments:
- Thales Luna SA 7 — Root CAs for WebPKI (DigiCert, Sectigo, Let's Encrypt use Luna HSMs)
- Utimaco SecurityServer — German banking infrastructure, Bundesbank, Deutsche Bank
- Entrust nShield — Microsoft Azure Dedicated HSM, government PKIs, TSPs
- Marvell LiquidSecurity — AWS CloudHSM backend
- Thales payShield 10K — Visa, Mastercard, every major payment processor

## Why it's stuck

- The ROM CA cert is burned at manufacture. Changing it requires hardware replacement —
 you cannot update the root of trust for firmware authentication without new hardware.
 For HSMs at Root CAs and payment networks, "replace all HSMs" is a multi-year project.
- HSM firmware updates are high-risk operations at CA/Browser Forum audited facilities.
 Change management, dual control, and ceremony procedures apply. A non-RSA firmware update
 would require all of this, plus vendor support.
- Thales, Utimaco, and nShield have not shipped any non-RSA firmware signing capability.
 Their HSMs don't support non-RSA algorithms in the bootloader.
- The firmware signing key is distinct from the keys the HSM protects. Even if HSMs get
 non-RSA key support (for storing ML-KEM keys), the firmware authentication mechanism itself
 remains RSA-2048 until the hardware is replaced.

## impact

this is the "root of roots" problem. HSMs are the hardware that's supposed to protect
everything else. if you can load arbitrary firmware into an HSM, "protected by HSM"
means nothing.

- find the Thales Luna RSA-2048 firmware signing cert. it's embedded in every Luna firmware
 update file (.fuf), which Thales distributes to customers. get one firmware file (published
 to Thales support portal, obtainable via any customer's support access, or via security
 research). extract the signing cert DER. factor the RSA-2048 key. derive the private key.
- sign a malicious Luna firmware image. the image runs inside the Luna HSM's secure boundary.
 it enumerates all key objects, uses the Luna API internally to export key material through
 a side channel. the Luna is now a key exfiltration device wearing HSM clothes.
- targets: a Root CA HSM containing the CA private key. compromise the firmware, extract the
 key, issue unlimited certificates. this is the Diginotar scenario (2011, Iran/MitM HTTPS
 for 300K Iranian Gmail users) but without needing to compromise the CA software — just the
 HSM firmware. every certificate issued by that CA is now suspect.
- payment HSMs: Utimaco/payShield holding zone master keys (ZMK) for interbank PIN encryption.
 extract ZMK -> decrypt all PIN blocks -> every PIN at every ATM and POS terminal using that
 HSM for key management. visa/mastercard payment networks are built on this.
- the meta-attack: RSA protects HSMs, HSMs protect RSA keys. the recursion bottoms out at the
 HSM firmware RSA key. crack that, and the entire hardware security model inverts.

## Code

`hsm_rsa_firmware.c` — `hsm_verify_firmware()` (RSA-2048 PKCS#1 v1.5 bootloader firmware
verification, X.509 cert chain to ROM CA), `hsm_malicious_firmware_note()` (firmware signing
cert locations in Thales Luna/Utimaco/nShield update packages, key exfiltration model).
Payment HSM and Root CA HSM deployment context. "Root of roots" analysis in comments.
