/*
 * Source: matrix-org/olm - https://gitlab.matrix.org/matrix-org/olm
 * File:   src/session.cpp + include/olm/ratchet.hh
 * License: Apache-2.0
 *
 * Relevant excerpt: Olm's X3DH key agreement uses Curve25519 throughout.
 *
 * Olm is the end-to-end encryption library used by Matrix/Element and
 * any Matrix client.  It implements a variant of the Signal X3DH (Extended
 * Triple Diffie-Hellman) protocol for session establishment, followed by
 * a Double Ratchet for forward secrecy.
 *
 * ALL key exchange in Olm uses Curve25519 (ECDH over Curve25519).
 * Like secp256k1, Curve25519 is broken by Shor's algorithm.
 *
 * Matrix has an open issue (matrix-org/matrix-spec#975) for PQC migration
 * but no implementation timeline.  Megolm (the multi-party version used
 * for room encryption) has the same vulnerability.
 *
 * Practical impact: every Matrix room's history, every Element DM ever sent,
 * is encrypted with keys negotiated via Curve25519.  A CRQC operator can
 * re-derive the Curve25519 session keys and decrypt all stored messages
 * (this is the "harvest now, decrypt later" scenario for chat history).
 */

/* X3DH session creation from an OlmMessage.
 * The initiator sends their ephemeral Curve25519 public key.
 * The responder performs 3 (or 4) Curve25519 DH operations:
 *   DH1 = DH(IK_a, SPK_b)   -- initiator identity vs responder signed prekey
 *   DH2 = DH(EK_a, IK_b)    -- initiator ephemeral vs responder identity
 *   DH3 = DH(EK_a, SPK_b)   -- initiator ephemeral vs responder signed prekey
 *   DH4 = DH(EK_a, OPK_b)   -- initiator ephemeral vs one-time prekey (opt.)
 * Master secret = KDF(DH1 || DH2 || DH3 || DH4)
 * All four DH operations are Curve25519. Zero algorithm agility.
 */
std::size_t olm::Session::new_inbound_session(
    Account & local_account,
    std::uint8_t const * their_identity_key, std::size_t their_identity_key_length,
    std::uint8_t const * one_time_key_message, std::size_t message_length
) {
    /* Decode the one-time prekey message to extract sender's keys */
    Unpickle<PreKeyMessageReader> reader(one_time_key_message, message_length);

    /* their_one_time_key_id selects which of our Curve25519 one-time
     * prekeys to use.  Every prekey is a Curve25519 keypair. */
    olm::OneTimeKey const * our_one_time_key = local_account.lookup_key(
        reader->one_time_key_id
    );

    /* Perform X3DH:
     * axolotl_get_identity_keys() fetches our Curve25519 identity keypair.
     * olm::curve25519_shared_secret() is called 3-4 times.
     * The output feeds into HKDF to derive the initial ratchet keys. */
    create_inbound_session(
        session,
        local_account.axolotl_get_identity_keys(),  /* our Curve25519 IK */
        *our_one_time_key,                           /* our Curve25519 OPK */
        reader                                       /* their Curve25519 keys */
    );

    return std::size_t(0); /* success */
}

/*
 * The ratchet header (from include/olm/ratchet.hh) shows the key type:
 *
 *   struct ChainKey {
 *       std::uint32_t index;
 *       std::uint8_t  key[CURVE25519_KEY_LENGTH];  // 32 bytes, always C25519
 *   };
 *
 *   struct SenderChain {
 *       Curve25519KeyPair ratchet_key;   // Curve25519 only
 *       ChainKey chain_key;
 *   };
 *
 * CURVE25519_KEY_LENGTH = 32 bytes hardcoded.
 * ML-KEM ciphertexts are 1088 bytes (ML-KEM-768) -- incompatible wire format.
 * Migration requires a new Olm version with an incompatible message format.
 */
