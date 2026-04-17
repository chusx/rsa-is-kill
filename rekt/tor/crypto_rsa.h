/*
 * Source: Tor Project - https://gitlab.torproject.org/tpo/core/tor
 * File:   src/lib/crypt_ops/crypto_rsa.h
 * License: BSD-3-Clause
 *
 * Relevant excerpt: Tor relay identity keys are RSA-1024.
 *
 * PK_BYTES = 1024/8 = 128 bytes.  Every relay on the Tor network is
 * identified by the SHA-1 fingerprint of its RSA-1024 public key.
 * This identity key signs the relay descriptor, which routers use to
 * authenticate the relay and build circuits.
 *
 * RSA-1024 is considered broken by classical standards (NIST deprecated
 * it in 2013).  It is catastrophically broken by Shor's algorithm.
 * A CRQC could impersonate ANY Tor relay, run a fully authenticated
 * man-in-the-middle on every Tor circuit, and de-anonymize users.
 *
 * Tor added ntor (Curve25519) for onion encryption in 0.2.4, and has
 * been slowly migrating identity to Ed25519, but the legacy RSA-1024
 * identity key is STILL REQUIRED as of 2026 for backward compatibility.
 * A relay that drops it cannot communicate with older relays.
 */

/** Length of our RSA keys. */
#define PK_BYTES (1024/8)             /* <-- RSA-1024: 128 bytes */

/** Constant used to indicate PKCS1 OAEP padding for public-key encryption */
#define PK_PKCS1_OAEP_PADDING 60002

/** The fixed public exponent used in all Tor RSA keys */
#define TOR_RSA_EXPONENT 65537

/** Length of encoded fingerprint: space-separated groups of 4 hex chars */
#define FINGERPRINT_LEN 49

crypto_pk_t *crypto_pk_new(void);
void crypto_pk_free_(crypto_pk_t *env);

/** Generate a <b>bits</b>-bit RSA key - called at relay startup */
int crypto_pk_generate_key_with_bits(crypto_pk_t *env, int bits);

/** Sign <b>fromlen</b> bytes of data from <b>from</b> with the private
 * key in <b>env</b>, using PKCS1 padding.  Store signature in <b>to</b>.
 * Used to sign relay descriptors that identify the relay to the network. */
int crypto_pk_private_sign(const crypto_pk_t *env, char *to, size_t tolen,
                           const char *from, size_t fromlen);

/** As crypto_pk_private_sign(), but compute the SHA1 digest first.
 * This is the function called when signing a relay descriptor. */
int crypto_pk_private_sign_digest(crypto_pk_t *env, char *to, size_t tolen,
                                  const char *from, size_t fromlen);

/** Check a signature: given the public key in <b>env</b>, a signature
 * <b>sig</b> of length <b>siglen</b>, and a digest <b>digested</b>,
 * verify the signature.  Used to authenticate relay identities. */
int crypto_pk_public_checksig(const crypto_pk_t *env, char *to,
                              size_t tolen, const char *from,
                              size_t fromlen);

/** As crypto_pk_public_checksig(), but also SHA1-digests the data first */
int crypto_pk_public_checksig_digest(crypto_pk_t *env, const char *data,
                                     size_t datalen, const char *sig,
                                     size_t siglen);

/** Return a fingerprint of the public key in <b>pk</b> - this IS
 * the relay's identity on the Tor network */
int crypto_pk_get_fingerprint(crypto_pk_t *pk, char *fp_out, int add_space);
