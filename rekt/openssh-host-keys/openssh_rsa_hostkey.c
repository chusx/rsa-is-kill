/*
 * openssh_rsa_hostkey.c
 *
 * Excerpted from openssh-portable (OpenBSD / openssh/openssh-portable on GitHub)
 * Source: ssh-rsa.c — RSA host key signing and verification
 *
 * SSH servers advertise their host key algorithm in the server_host_key_algorithms
 * field of SSH_MSG_KEXINIT. "ssh-rsa" means RSA-2048 or RSA-4096 with SHA-1 or SHA-2.
 * The host key is used during key exchange to prove server identity.
 *
 * If the RSA host private key is derived from the public key (via CRQC), an
 * attacker can impersonate any SSH server whose public host key they have seen —
 * including every server whose key has been scanned by Shodan or similar.
 */

#include "includes.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "sshkey.h"
#include "ssherr.h"
#include "digest.h"

/* From openssh-portable ssh-rsa.c */

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";           /* RFC 4253 — SHA-1, deprecated but still negotiated */
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";      /* RFC 8332 */
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";      /* RFC 8332 */
	}
	return NULL;
}

/*
 * ssh_rsa_sign() — server signs the session exchange hash with its RSA host key.
 * This is what a client verifies to confirm it's talking to the right server.
 * Source: openssh-portable ssh-rsa.c ssh_rsa_sign()
 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	RSA *rsa;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig = NULL;
	size_t slen = 0;
	u_int dlen, len;
	int nid, hash_alg, ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	/* RSA key size check — minimum 1024 bits, but RSA-2048 is standard for host keys */
	if (RSA_bits(key->rsa) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	rsa = key->rsa;

	/* hash_alg is SHA-256 or SHA-512 (rsa-sha2-256/rsa-sha2-512) or SHA-1 (ssh-rsa) */
	if ((hash_alg = rsa_hash_alg_from_ident(alg_ident)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((nid = rsa_hash_alg_nid(hash_alg)) == -1)
		return SSH_ERR_INTERNAL_ERROR;

	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	dlen = ssh_digest_bytes(hash_alg);
	slen = RSA_size(rsa);
	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * PKCS#1 v1.5 signature with RSA private key.
	 * The private key is what a CRQC derives from the public host key.
	 * Public host keys are stored in ~/.ssh/known_hosts on every client,
	 * scanned by Shodan/Censys/ZoomEye, and logged by network middleboxes.
	 */
	if (RSA_sign(nid, digest, dlen, sig, &len, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* ... pack into SSH wire format wire format sshbuf ... */
	ret = 0;
out:
	explicit_bzero(digest, sizeof(digest));
	return ret;
}

/*
 * ssh_rsa_verify() — client verifies server's RSA host key signature.
 * Source: openssh-portable ssh-rsa.c ssh_rsa_verify()
 */
int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	RSA *rsa;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	u_char *osigblob = NULL;
	const u_char *sigblob;
	size_t len, diff, modlen;
	int nid, hash_alg, ret;
	u_int dlen;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if (RSA_bits(key->rsa) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	rsa = key->rsa;

	if ((hash_alg = rsa_hash_alg_from_ident(alg_ident)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((nid = rsa_hash_alg_nid(hash_alg)) == -1)
		return SSH_ERR_INTERNAL_ERROR;

	/* ... parse wire format to get sigblob, len ... */

	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	dlen = ssh_digest_bytes(hash_alg);

	/*
	 * RSA_verify() checks the PKCS#1 v1.5 signature using the server's
	 * public key. The public key (n, e) is what a CRQC uses as input to
	 * factor n and recover the private key d.
	 */
	if (RSA_verify(nid, digest, dlen, osigblob, len, rsa) != 1) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ret = 0;
out:
	explicit_bzero(digest, sizeof(digest));
	free(osigblob);
	return ret;
}

/*
 * Host key generation — called by ssh-keygen or sshd on first start.
 * Generates the RSA keypair stored in /etc/ssh/ssh_host_rsa_key.
 * The public key is sent to every client that connects.
 */
int
generate_rsa_host_key(int bits)  /* bits = 3072 default in recent OpenSSH, 2048 common */
{
	struct sshkey *private = NULL;
	int r;

	if ((r = sshkey_generate(KEY_RSA, bits, &private)) != 0)
		return r;

	/* saves to /etc/ssh/ssh_host_rsa_key and /etc/ssh/ssh_host_rsa_key.pub */
	/* public key in .pub is what gets stored in client known_hosts */
	/* and indexed by internet scanners */
	return 0;
}
