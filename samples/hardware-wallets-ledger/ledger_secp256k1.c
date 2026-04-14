/*
 * Source: Ledger Developer Portal (public SDK)
 *         https://developers.ledger.com/docs/device-app/references/cryptography-api
 *         LedgerHQ/app-bitcoin-new - https://github.com/LedgerHQ/app-bitcoin-new
 * License: Apache-2.0 (app-bitcoin-new), proprietary (SDK internals)
 *
 * Relevant excerpt: Ledger devices sign with secp256k1 ECDSA / Ed25519.
 * Hardware wallets ARE the last line of defense for private key security.
 * If the signing algorithm is broken, the hardware's isolation doesn't help.
 *
 * Ledger's cryptography API exposes:
 *   cx_ecdsa_sign()  - secp256k1 / NIST curves ECDSA
 *   cx_eddsa_sign()  - Ed25519 / Ed448
 * No PQC primitive exists in the Ledger SDK.
 *
 * The Trezor Safe 7 added SLH-DSA for firmware signing (boot chain)
 * but Bitcoin/Ethereum transactions still use secp256k1 ECDSA - because
 * the blockchain protocol requires it, not the hardware.
 *
 * Practical impact: hardware wallet security is irrelevant to quantum
 * attacks.  The private key never leaves the device, but Shor's algorithm
 * attacks the PUBLIC key (which IS on-chain).  It doesn't matter how
 * secure the private key storage is if the public key leaks the private key.
 */

#include "cx.h"   /* Ledger SDK cryptography API */

/*
 * Sign a Bitcoin transaction hash with secp256k1 ECDSA.
 * Called by the Bitcoin app when the user confirms a transaction.
 * The private key lives in the Ledger's secure element (STM32 + SE050).
 * The PUBLIC key is permanently on the blockchain - quantum-attackable.
 */
cx_err_t sign_bitcoin_transaction(
    const uint8_t *tx_hash,     /* 32-byte SHA256d hash of transaction */
    uint8_t       *signature,   /* output: DER-encoded ECDSA signature */
    size_t        *sig_len,
    uint32_t      *info         /* parity bit for public key recovery */
)
{
    cx_ecfp_private_key_t private_key;
    uint8_t private_key_data[32];

    /* Derive the private key from the HD wallet seed for this BIP32 path.
     * The key never leaves the secure element in plaintext. */
    os_perso_derive_node_bip32(CX_CURVE_256K1,   /* secp256k1 - hardcoded */
                                bip32_path, bip32_path_len,
                                private_key_data, NULL);

    cx_ecfp_init_private_key(CX_CURVE_256K1,      /* secp256k1 - hardcoded */
                              private_key_data, 32,
                              &private_key);

    /*
     * cx_ecdsa_sign: ECDSA signature over secp256k1.
     * CX_RND_RFC6979: RFC 6979 deterministic nonce (same as Bitcoin Core).
     * CX_LAST: finalize and produce the signature.
     *
     * The hardware isolation protects against software extraction of
     * private_key_data.  It does NOT protect against Shor's algorithm,
     * which only needs the PUBLIC key (available on-chain) to recover
     * the private key without ever touching the hardware.
     */
    return cx_ecdsa_sign(
        &private_key,
        CX_RND_RFC6979 | CX_LAST,
        CX_SHA256,
        tx_hash, 32,
        signature, sig_len,
        info
    );
}

/*
 * The corresponding public key lookup - this is what's on the blockchain.
 * cx_ecfp_generate_pair() derives it from the private key.
 * Once this public key is on-chain, it is permanently quantum-vulnerable.
 *
 * Ledger's response to the quantum threat:
 *   "Post-quantum cryptography would require new hardware capable of
 *    handling the larger key sizes and computational demands of PQC.
 *    Current Secure Element chips lack the processing power for PQC."
 *
 * There is no firmware update path that adds PQC to existing hardware.
 * Every Ledger Nano S/X/S Plus ever sold is permanently secp256k1-only.
 */
cx_err_t get_public_key(
    cx_ecfp_public_key_t *public_key,  /* output: 65-byte uncompressed point */
    const uint8_t        *private_key_data
)
{
    cx_ecfp_private_key_t private_key;
    cx_ecfp_init_private_key(CX_CURVE_256K1, private_key_data, 32, &private_key);
    return cx_ecfp_generate_pair(CX_CURVE_256K1,   /* secp256k1 - hardcoded */
                                  public_key,
                                  &private_key,
                                  1 /* keep_private */);
}
