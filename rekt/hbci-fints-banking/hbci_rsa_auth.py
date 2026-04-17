"""
hbci_rsa_auth.py

German HBCI / FinTS online banking — RSA-2048 authentication.
Repository: python-fints (https://github.com/raphaelm/python-fints)
            aqbanking (https://www.aquamaniac.de/rdm/projects/aqbanking)

HBCI (Homebanking Computer Interface) is the German banking standard for
online banking, standardized by the German Banking Industry Committee (ZKA/DK).
FinTS (Financial Transaction Services) is the current version (FinTS 4.1).

HBCI/FinTS is used by virtually all German banks:
  - Deutsche Bank, Commerzbank, Dresdner Bank
  - Sparkassen (Germany's largest banking group by customers, ~50M accounts)
  - Volksbanken / Raiffeisenbanken (cooperative banking group, ~30M accounts)
  - DZ Bank, Landesbanken
  - ING-DiBa, Comdirect, Consorsbank (direct banks)

Authentication methods:
  - PIN+TAN (most consumer accounts): username/password + one-time password
  - HBCI chipcard (Eurocard/GeldKarte): smartcard with RSA keypair
  - RDH (RSA Diffie-Hellman): software-based RSA-2048 keys in a keyfile

RDH (RSA Diffie-Hellman) is the security level used by:
  - Business banking customers (Firmenkunden)
  - Direct banking customers who want key-based auth
  - Accounting software integrations (DATEV, Lexware, etc.)

RDH-10 is the current profile: RSA-2048 authentication key + RSA-2048 encryption key.
Both keys are stored in a keyfile (HBCI keyfile, .RDH or .KBF format) encrypted
with a user passphrase. The bank also stores the user's RSA public key.

The bank authenticates each FinTS message by verifying the RSA signature on the
message header. An attacker who derives the user's RSA private key can send
arbitrary FinTS transactions authenticated as that user.

This module is a simplified model based on the python-fints library and the
FinTS 4.1 specification documents published by the Deutsche Kreditwirtschaft.
"""

import hashlib
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# FinTS 4.1 RDH-10 profile constants
FINTS_RDH10_KEY_LEN = 2048     # RSA-2048 for both auth and encryption keys
FINTS_RDH10_HASH_ALG = "SHA-256"
FINTS_SIGNATURE_ALG = "6"      # FinTS algorithm ID for RSA PKCS#1 v1.5


def hbci_load_keyfile(keyfile_path: str, passphrase: str) -> dict:
    """
    Load HBCI/FinTS RDH keyfile.

    The HBCI keyfile contains two RSA-2048 keypairs:
      - Authentication key (Signierschlüssel): signs outgoing FinTS messages
      - Encryption key (Chiffrierschlüssel): decrypts incoming encrypted messages

    The keyfile is in a proprietary format specific to each banking software.
    python-fints uses a custom format; aqbanking uses its own.
    Both store the RSA keypairs encrypted with the user passphrase.

    The bank's public keys (for verifying bank responses) are also stored in the
    keyfile, fetched from the bank's HBCI server during initial registration.

    Returns dict with:
      'auth_key': RSA private key object (RSA-2048)
      'enc_key': RSA private key object (RSA-2048)
      'bank_auth_pubkey': RSA public key for bank signature verification
      'bank_enc_pubkey': RSA public key for message encryption to bank
    """
    # Real implementation: decrypt keyfile with passphrase, parse binary format
    # Returns RSA key objects
    # Simplified: this would call aqbanking's AB_Banking_LoadKeyfile() or
    # python-fints FinTSKeyFile class
    raise NotImplementedError("keyfile parsing is vendor-specific binary format")


def hbci_sign_message(message_body: bytes, auth_key) -> bytes:
    """
    Sign a FinTS message with the user's RSA-2048 authentication key.

    Called before sending any FinTS transaction request (HKUEB for wire transfer,
    HKSAL for balance query, HKDPB for standing orders, etc.).

    FinTS message signature structure (simplified):
        HNSHK (signature header segment):
            Security profile: RDH 10
            Algorithm: 6 (RSA PKCS#1 v1.5)
            Hash algorithm: SHA-256
            Key name: customer/bank ID + key number + key version
            Reference number: unique per message

        [message segments: HKUEB for transfer, etc.]

        HNSHA (signature trailer segment):
            Reference to HNSHK
            Validation result: (empty in outgoing messages)
            User signature: RSA-SHA256 PKCS#1 v1.5 of the message body

    The bank's FinTS server verifies this signature using the user's RSA-2048
    public key stored in the bank's system from the initial registration.
    If the signature is invalid, the transaction is rejected.
    If an attacker derives the user's RSA private key, all transactions pass.
    """
    # SHA-256 of the message body (the segments between HNSHK and HNSHA)
    digest = hashlib.sha256(message_body).digest()

    # RSA-2048 PKCS#1 v1.5 signature
    signature = auth_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature  # 256 bytes for RSA-2048


def hbci_verify_bank_response(response_body: bytes, bank_auth_pubkey,
                                bank_signature: bytes) -> bool:
    """
    Verify the bank's RSA signature on a FinTS response message.

    The bank also signs its responses (balance, transaction history, etc.)
    with the bank's RSA-2048 authentication key. The user's software verifies
    this signature using the bank public key stored in the keyfile.

    The bank's RSA public key was fetched during initial key registration
    (HKVVB / INI dialog). It's stored in the keyfile.

    This prevents MITM — an attacker who intercepts the FinTS connection
    cannot forge a bank response because they don't have the bank's RSA private key.

    UNLESS they can factor the bank's RSA-2048 public key from the keyfile.
    Then they can forge any bank response: fake balance, fake transaction history,
    fake confirmation that a wire transfer was rejected (when it went through).
    """
    try:
        bank_auth_pubkey.verify(
            bank_signature,
            response_body,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def hbci_encrypt_message(message: bytes, bank_enc_pubkey) -> bytes:
    """
    Encrypt FinTS message with the bank's RSA-2048 encryption key.

    FinTS uses a hybrid encryption scheme (like most RSA protocols):
      1. Generate a random AES-256 session key
      2. Encrypt the session key with the bank's RSA-2048 encryption key (PKCS#1 v1.5)
      3. Encrypt the message with AES-256

    The encrypted session key and ciphertext are wrapped in:
        HNVSK (encryption header): RSA-encrypted session key
        HNVSD (encryption data): AES-encrypted message body

    An attacker who factors the bank's RSA-2048 encryption key can decrypt
    any intercepted FinTS session (HNDL attack on recorded banking traffic).
    """
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Generate AES-256 session key
    session_key = os.urandom(32)

    # RSA-PKCS1v15 encrypt session key with bank's public key
    encrypted_session_key = bank_enc_pubkey.encrypt(session_key, padding.PKCS1v15())

    # AES-256-CBC encrypt message
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + b'\x00' * (16 - len(message) % 16)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Return HNVSK + HNVSD structure
    return encrypted_session_key + iv + ciphertext


# German banking deployment context:
#
# FinTS/HBCI RDH is used by the DATEV integration for tax advisors and accountants.
# DATEV is used by ~80% of German tax firms. Every DATEV client with a business
# bank account has a HBCI keyfile with RSA-2048 keys.
#
# aqbanking is the open-source HBCI/FinTS client library used by:
#   - GnuCash (personal finance)
#   - KMyMoney
#   - Hibiscus (standalone Java HBCI client)
#   - Various German accounting software integrations
#
# The Sparkassen and Volksbanken HBCI servers accept RDH-10 (RSA-2048) transactions.
# An attacker who factors any customer's RSA-2048 authentication key can initiate
# wire transfers from that account to any IBAN. The bank verifies the RSA signature;
# no OTP or additional factor is required for RDH-authenticated transactions.
#
# HBCI keyfiles are stored on user machines, often backed up to cloud storage.
# They're encrypted with a passphrase, but the RSA public key is in plaintext
# in the keyfile and is also registered with the bank. Both are CRQC inputs.
