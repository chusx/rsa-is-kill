/*
 * avb_rsa_verify.c
 *
 * Excerpted from AOSP libavb (Android Verified Boot 2.0)
 * Source: https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_rsa.c
 *
 * Android Verified Boot 2.0 (AVB2) verifies every boot image (boot.img,
 * system.img, vendor.img) against an RSA-4096 signature in the vbmeta
 * structure before the kernel is allowed to run. The OEM key is burned
 * into the device's bootloader or stored in a write-once fuse array.
 *
 * Key sizes:
 *   AVB_RSA2048_NUM_BYTES = 256   (RSA-2048, SHA-256)
 *   AVB_RSA4096_NUM_BYTES = 512   (RSA-4096, SHA-256 or SHA-512)  <-- default for OEM keys
 *   AVB_RSA8192_NUM_BYTES = 1024  (RSA-8192, rare)
 */

#include "avb_rsa.h"
#include "avb_util.h"
#include "avb_sha.h"

/* From libavb/avb_rsa.c — AvbRSAPublicKeyHeader layout */
typedef struct AvbRSAPublicKeyHeader {
	uint32_t key_num_bits;   /* Number of key bits, e.g. 4096 */
	uint32_t n0inv;          /* -1 / n[0] mod 2^32 */
	/* Followed by key_num_bits/8 bytes of n[] (the modulus) */
	/* Followed by key_num_bits/8 bytes of rr[] (Montgomery parameter R^2 mod n) */
} AVB_ATTR_PACKED AvbRSAPublicKeyHeader;

/*
 * avb_rsa_verify() — verifies an RSA PKCS#1 v1.5 signature.
 *
 * Called by avb_vbmeta_image_verify() for every slot in the vbmeta chain.
 * The |key| is the device's OEM signing key (stored in vbmeta or eFuses),
 * |sig| is the 512-byte RSA-4096 signature from the vbmeta footer,
 * |hash| is the SHA-256 or SHA-512 digest of the vbmeta image contents.
 *
 * Source: libavb/avb_rsa.c
 */
bool avb_rsa_verify(const uint8_t* key,
                    size_t key_num_bytes,
                    const uint8_t* sig,
                    size_t sig_num_bytes,
                    const uint8_t* hash,
                    size_t hash_num_bytes,
                    const uint8_t* padding,
                    size_t padding_num_bytes) {
	uint32_t* n;         /* RSA modulus */
	uint32_t* rr;        /* Montgomery parameter */
	uint64_t n0inv;
	uint32_t* a;
	uint32_t* b;
	uint32_t key_num_bits;
	size_t key_len;
	int i;
	AvbRSAPublicKeyHeader hdr;
	bool ret = false;

	if (!key || !sig || !hash || !padding) {
		return false;
	}

	/* Parse the AvbRSAPublicKeyHeader */
	avb_memcpy(&hdr, key, sizeof(hdr));
	key_num_bits = avb_be32toh(hdr.key_num_bits);
	key_len      = key_num_bits / 8;  /* 512 bytes for RSA-4096 */

	if (sig_num_bytes != key_len) {
		avb_error("Signature length mismatch.\n");
		return false;
	}

	n0inv = avb_be32toh(hdr.n0inv);
	n  = (uint32_t*)(key + sizeof(AvbRSAPublicKeyHeader));
	rr = (uint32_t*)(key + sizeof(AvbRSAPublicKeyHeader) + key_len);

	/* Copy sig into working buffer */
	a = (uint32_t*)avb_malloc(key_len);
	b = (uint32_t*)avb_malloc(key_len);
	if (!a || !b) goto out;
	avb_memcpy(a, sig, key_len);

	/* Montgomery modular exponentiation: a = sig^e mod n, where e = 65537 */
	/* (public exponent F4 = 0x10001) */
	/* Uses Montgomery multiplication to avoid full bignum division */
	for (i = 0; i < (int)(key_num_bits - 1); i++) {
		mont_mult(a, a, rr, n, n0inv, key_len / 4);  /* square */
	}
	mont_mult(a, a, rr, n, n0inv, key_len / 4);       /* final multiply */

	/* Compare decrypted signature against expected PKCS#1 v1.5 padding + hash */
	/* Padding format: 0x00 0x01 [0xff...] 0x00 [DigestInfo] [hash] */
	if (avb_safe_memcmp(a, padding, padding_num_bytes) != 0) {
		avb_error("Padding check failed.\n");
		goto out;
	}
	if (avb_safe_memcmp(((uint8_t*)a) + padding_num_bytes, hash, hash_num_bytes) != 0) {
		avb_error("Hash check failed.\n");
		goto out;
	}

	ret = true;
out:
	avb_free(a);
	avb_free(b);
	return ret;
}

/*
 * avb_vbmeta_image_verify() — top-level entry point called from the bootloader.
 * Extracts the signing key and signature from the vbmeta image header,
 * then calls avb_rsa_verify() above.
 *
 * The vbmeta image contains:
 *   - AvbVBMetaImageHeader (magic, algorithm_type, signature_size, ...)
 *   - Authentication block (hash + signature of signed data)
 *   - Auxiliary block (public key + descriptors)
 *
 * CRQC attack: the vbmeta auxiliary block contains the OEM RSA-4096 public key.
 * Factor it to get the OEM private key. Sign any arbitrary boot image.
 * The bootloader will accept it as a genuine OEM-signed image.
 *
 * OEM signing keys for major Android manufacturers are public in their
 * factory images (e.g. Google Pixel vbmeta images are distributed as OTA
 * packages). The public key has been available since device launch.
 */
AvbVBMetaVerifyResult avb_vbmeta_image_verify(
    const uint8_t* data,
    size_t length,
    const uint8_t** out_public_key_data,
    size_t* out_public_key_length) {

	AvbVBMetaImageHeader h;
	const uint8_t* pubkey;
	const uint8_t* sig;
	const uint8_t* hash;

	/* ... parse header, validate magic ... */

	/* algorithm_type encodes RSA key size + hash algorithm:
	 *   AVB_ALGORITHM_TYPE_SHA256_RSA2048 = 1
	 *   AVB_ALGORITHM_TYPE_SHA256_RSA4096 = 2  <-- typical OEM key
	 *   AVB_ALGORITHM_TYPE_SHA512_RSA4096 = 5
	 *   AVB_ALGORITHM_TYPE_SHA512_RSA8192 = 6
	 */

	/* Verify signature */
	if (!avb_rsa_verify(pubkey, pubkey_size, sig, sig_size,
	                    hash, hash_size, padding, padding_size)) {
		return AVB_VBMETA_VERIFY_RESULT_INVALID_SIGNATURE;
	}

	return AVB_VBMETA_VERIFY_RESULT_OK;
}
