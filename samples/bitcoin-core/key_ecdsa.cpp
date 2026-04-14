/*
 * Source: Bitcoin Core - https://github.com/bitcoin/bitcoin
 * File:   src/key.cpp
 * License: MIT
 *
 * Relevant excerpt: ECDSA signing over secp256k1.
 * Every Bitcoin transaction output is locked to a secp256k1 public key
 * or its hash.  Spending requires a valid ECDSA (or Schnorr) signature
 * under that key.  secp256k1 is not post-quantum: Shor's algorithm
 * recovers the private key from the public key in polynomial time on a
 * CRQC.  There is no protocol-level migration path without a consensus
 * hard fork.  ~4 million BTC sit in P2PK outputs whose public keys are
 * already exposed on-chain.
 */

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig,
                bool grind, uint32_t test_case) const
{
    if (!keydata) return false;

    vchSig.resize(CPubKey::SIGNATURE_SIZE);
    size_t nSigLen = CPubKey::SIGNATURE_SIZE;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);

    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;

    /* RFC 6979 deterministic nonce - still ECDSA over secp256k1 */
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig,
                                   hash.begin(),
                                   UCharCast(begin()),
                                   secp256k1_nonce_function_rfc6979,
                                   (!grind && test_case) ? extra_entropy : nullptr);

    /* "low-R grinding": retry with incremented counter until the
       signature's R value has a leading zero byte (saves 1 byte in
       DER encoding).  Still fundamentally ECDSA. */
    while (ret && !SigHasLowR(&sig) && grind) {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig,
                                   hash.begin(),
                                   UCharCast(begin()),
                                   secp256k1_nonce_function_rfc6979,
                                   extra_entropy);
    }

    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static,
                                            vchSig.data(), &nSigLen, &sig);
    vchSig.resize(nSigLen);

    /* Immediately verify to catch hardware glitches */
    secp256k1_pubkey pk;
    ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk,
                                     UCharCast(begin()));
    ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig,
                                 hash.begin(), &pk);
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const
{
    if (pubkey.IsCompressed() != fCompressed) return false;
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd);
    uint256 hash{Hash(str, rnd)};
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}
