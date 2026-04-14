/*
 * suci_ecdh_concealment.c
 *
 * 5G NR SUCI (Subscription Concealed Identifier) — ECDH-based SUPI concealment.
 * Standard: 3GPP TS 33.501 §6.12, Annex C
 * Source: open5gs (open5gs/open5gs) — https://github.com/open5gs/open5gs
 *         sysmocom/srsRAN_4G, free5GC/free5gc
 *         UE side: osmocom/pysim (SIM card tools)
 *
 * In 5G NR, the permanent subscriber identity (SUPI = IMSI) is never sent
 * in plaintext over the radio interface. Instead, the UE (phone) conceals it
 * using an ECIES scheme with the Home Network's public key.
 *
 * The result is the SUCI (Subscription Concealed Identifier), sent in
 * registration requests. Only the Home Network (AUSF/UDM) can decrypt it.
 *
 * 3GPP TS 33.501 defines two Protection Schemes:
 *   Profile A: X25519 (Curve25519 ECDH) + HKDF + AES-128-CTR + HMAC-SHA-256
 *   Profile B: secp256r1 (P-256 ECDH)  + HKDF + AES-128-CTR + HMAC-SHA-256
 *
 * Both X25519 and P-256 are classical elliptic curves broken by Shor's algorithm.
 * The Home Network Public Key is provisioned into the SIM/USIM at manufacture
 * or via OTA update. SIM cards have 3-5 year replacement cycles.
 *
 * 3GPP SA3 has no standardized PQC protection scheme for SUCI.
 * The 5G SUCI protection scheme IDs 0-2 are reserved; no PQC scheme registered.
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include "ogs-crypt.h"  /* open5gs crypto utilities */

/* 3GPP TS 33.501 Annex C: SUCI Protection Scheme identifiers */
#define SUCI_PROTECTION_SCHEME_NULL    0x0  /* no concealment (emergency) */
#define SUCI_PROTECTION_SCHEME_PROFILE_A  0x1  /* X25519 */
#define SUCI_PROTECTION_SCHEME_PROFILE_B  0x2  /* secp256r1 / P-256 */

/* Home Network Public Key identifier (1 byte, 0-255) */
/* Identifies which HN public key the UE used for concealment */

/*
 * suci_scheme_b_conceal() — Profile B SUCI concealment using secp256r1.
 *
 * Called on the UE (phone) side to conceal the SUPI before transmission.
 * The home_network_pubkey is stored in the SIM card (USIM EF SUCI Calc Info).
 *
 * Source: open5gs lib/crypt/ogs-suci.c ogs_suci_profile_b_encrypt()
 */
int suci_scheme_b_conceal(
    const uint8_t *supi_scheme_input,  /* MSIN portion of SUPI */
    size_t msin_len,
    const EC_KEY *home_network_pubkey, /* secp256r1 public key from SIM EF */
    uint8_t hnpubkey_id,               /* home network public key index */
    uint8_t *suci_out,                 /* output SUCI */
    size_t *suci_len)
{
	EC_KEY *ue_ephemeral_key = NULL;
	const EC_GROUP *group;
	uint8_t ecdh_shared_secret[32];  /* P-256 shared secret = 32 bytes */
	uint8_t encr_key[16];            /* AES-128 encryption key from HKDF */
	uint8_t mac_key[32];             /* HMAC-256 key from HKDF */
	uint8_t encrypted_msin[16];      /* AES-128-CTR encrypted MSIN */
	uint8_t mac_tag[8];              /* truncated HMAC-SHA-256 MAC tag */
	uint8_t ue_pubkey_compressed[33];/* compressed P-256 ephemeral public key */
	size_t pubkey_len = 33;

	/* Generate UE ephemeral P-256 keypair */
	ue_ephemeral_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); /* secp256r1 */
	if (!ue_ephemeral_key) goto err;
	if (!EC_KEY_generate_key(ue_ephemeral_key)) goto err;

	/* ECDH: shared_secret = UE_ephemeral_private * HN_public_key (on P-256) */
	/* The x-coordinate of the resulting EC point is the shared secret */
	if (!ECDH_compute_key(ecdh_shared_secret, sizeof(ecdh_shared_secret),
	                      EC_KEY_get0_public_key(home_network_pubkey),
	                      ue_ephemeral_key, NULL))
		goto err;

	/*
	 * HKDF-SHA-256 key derivation (3GPP TS 33.501 Annex C.4):
	 *   encr_key || mac_key = HKDF(ecdh_shared_secret, "suci-profile-b")
	 */
	suci_hkdf_profile_b(ecdh_shared_secret, sizeof(ecdh_shared_secret),
	                    encr_key, mac_key);

	/* AES-128-CTR encryption of the MSIN */
	suci_aes_ctr_encrypt(encr_key, supi_scheme_input, msin_len, encrypted_msin);

	/* HMAC-SHA-256 MAC (truncated to 64 bits) over encrypted MSIN */
	suci_hmac_mac(mac_key, encrypted_msin, msin_len, mac_tag);

	/* Serialize UE ephemeral public key (compressed, 33 bytes for P-256) */
	EC_POINT_point2oct(EC_KEY_get0_group(ue_ephemeral_key),
	                   EC_KEY_get0_public_key(ue_ephemeral_key),
	                   POINT_CONVERSION_COMPRESSED,
	                   ue_pubkey_compressed, pubkey_len, NULL);

	/*
	 * SUCI output format (3GPP TS 33.501 §6.12.2):
	 * [SUPI type=0][Home Network Identifier][Routing Indicator]
	 * [Protection Scheme ID=0x02][Home Network Public Key ID]
	 * [ECC Ephemeral Public Key (33 bytes)][Encrypted MSIN][MAC tag (8 bytes)]
	 */
	build_suci(suci_out, suci_len,
	           SUCI_PROTECTION_SCHEME_PROFILE_B, hnpubkey_id,
	           ue_pubkey_compressed, pubkey_len,
	           encrypted_msin, msin_len,
	           mac_tag, sizeof(mac_tag));

	EC_KEY_free(ue_ephemeral_key);
	return 0;
err:
	EC_KEY_free(ue_ephemeral_key);
	return -1;
}

/*
 * suci_scheme_b_decrypt() — Home Network AUSF/UDM decrypts the SUCI.
 *
 * Called on the Home Network side (AUSF or UDM) to recover the SUPI
 * from a received SUCI in a 5G Registration Request.
 *
 * Source: open5gs lib/crypt/ogs-suci.c ogs_suci_profile_b_decrypt()
 * Also: free5gc UDM, srsRAN core network
 */
int suci_scheme_b_decrypt(
    const uint8_t *ue_ephemeral_pubkey, /* 33-byte compressed P-256 point */
    const uint8_t *encrypted_msin,
    size_t msin_len,
    const uint8_t *mac_tag,
    const EC_KEY *hn_private_key,       /* Home Network P-256 private key */
    uint8_t *supi_out)
{
	uint8_t ecdh_shared_secret[32];
	uint8_t encr_key[16];
	uint8_t mac_key[32];
	EC_POINT *ue_pubkey_point = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(hn_private_key);

	/* Deserialize UE ephemeral public key */
	ue_pubkey_point = EC_POINT_new(group);
	EC_POINT_oct2point(group, ue_pubkey_point,
	                   ue_ephemeral_pubkey, 33, NULL);

	/*
	 * ECDH: shared_secret = HN_private_key * UE_ephemeral_public_key
	 *
	 * The Home Network private key is stored in the AUSF/UDM HSM.
	 * The Home Network public key (used by billions of SIMs) is in
	 * USIM EF SUCI Calc Info (EF_SUCI), provisioned by the operator.
	 *
	 * A CRQC solving ECDLP on P-256 derives the HN private key from
	 * the HN public key (which is in every SIM the operator has issued).
	 * With the HN private key, every SUCI can be decrypted.
	 * The SUCI was designed to prevent tracking by passive observers.
	 * A CRQC operator becomes an omniscient passive observer: every
	 * registration request reveals the subscriber's SUPI (IMSI).
	 */
	ECDH_compute_key(ecdh_shared_secret, sizeof(ecdh_shared_secret),
	                 ue_pubkey_point, hn_private_key, NULL);

	suci_hkdf_profile_b(ecdh_shared_secret, sizeof(ecdh_shared_secret),
	                    encr_key, mac_key);

	/* Verify MAC tag */
	if (!suci_verify_mac(mac_key, encrypted_msin, msin_len, mac_tag))
		return -1;

	/* Decrypt MSIN */
	suci_aes_ctr_decrypt(encr_key, encrypted_msin, msin_len, supi_out);

	EC_POINT_free(ue_pubkey_point);
	return 0;
}

/*
 * Deployment scale:
 *
 * As of 2025, 5G NR is deployed in 100+ countries with 1.5+ billion
 * 5G subscriptions. Every 5G-capable SIM card implements SUCI concealment.
 * Profile A (X25519) and Profile B (P-256) are both standard.
 *
 * The Home Network Public Key (HNPK) is managed by the operator and
 * provisioned into SIMs at manufacture or via OTA USIM update (ETSI TS 131 102).
 * SIM cards have 3-5 year replacement cycles in consumer markets.
 * IoT SIMs have 10+ year lifespans.
 *
 * A CRQC breaking the HNPK (P-256 or X25519):
 *   - Decrypts SUCI in every registration request -> tracks subscriber location
 *     in real-time using 5G registration signaling (SUCI appears in every
 *     cell reselection, handover, and idle mode paging response)
 *   - Correlates SUPI to SUCI -> permanent subscriber de-anonymization
 *   - The 5G privacy architecture (designed to defeat IMSI catchers) collapses
 */
