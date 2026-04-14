/*
 * dlms_cosem_rsa.c
 *
 * DLMS/COSEM (IEC 62056) smart meter security — RSA key agreement.
 * Source: GuruxDLMS.c — https://github.com/Gurux/GuruxDLMS.c
 * Reference: gurux/GuruxDLMS.c/blob/master/development/src/dlms.c
 *            gurux/GuruxDLMS.c/blob/master/development/src/ciphering.c
 *
 * DLMS/COSEM is the dominant protocol for smart electricity, gas, and water
 * meters worldwide. IEC 62056-8-3 defines the security suite:
 *
 *   Security Suite 0: AES-128 (symmetric, no PKC)
 *   Security Suite 1: AES-128 + ECDH P-256 + ECDSA P-256 (NIST curves)
 *   Security Suite 2: AES-256 + ECDH P-384 + ECDSA P-384 (NIST curves)
 *
 * The global meter base is approximately 1 billion smart meters deployed
 * with IEC 62056 Security Suite 1 (ECDH P-256 / ECDSA P-256).
 * Security Suite 2 (P-384) is used in higher-security deployments.
 *
 * Both P-256 and P-384 are classical ECDSA/ECDH curves broken by
 * Shor's algorithm. The IEC 62056 series has no PQC security suite defined.
 * The IEC TC57 WG14 responsible for the standard has no PQC roadmap.
 *
 * Smart meters have:
 *   - 10-15 year deployment lifespans
 *   - Firmware update capability (varies by deployment)
 *   - Keys burned at manufacture in many deployments
 */

#include "dlms.h"
#include "ciphering.h"
#include "gxEcdsa.h"

/*
 * DLMS Security Suite 1 key agreement using ECDH P-256.
 *
 * The DLMS key agreement process (IEC 62056-8-3 §7.3.2):
 *   1. Meter and head-end each have ECDSA P-256 key pairs (long-term identity)
 *   2. ECDH P-256 ephemeral key exchange establishes a shared secret
 *   3. Shared secret is used to derive AES-128 session keys
 *
 * Source: GuruxDLMS.c development/src/ciphering.c
 * gxCiphering_KeyAgreement()
 */
int dlms_key_agreement_suite1(
    gxEccKeyPair *local_key,          /* meter's P-256 key pair */
    gxByteBuffer *remote_public_key,  /* head-end's P-256 ephemeral public key */
    gxByteBuffer *shared_secret)      /* output: 32-byte ECDH shared secret */
{
	/*
	 * ECDH on P-256: compute local_private_key * remote_public_point.
	 * The x-coordinate of the result is the shared secret.
	 *
	 * CRQC: a CRQC solving ECDLP on P-256 derives the private key from
	 * the public key. With the private key, the attacker computes the same
	 * shared secret as the meter. All historical key agreements are
	 * retroactively compromised (HNDL risk for long-term meter data).
	 */
	return gxEcdsa_KeyAgreement(local_key, remote_public_key, shared_secret);
}

/*
 * DLMS ECDSA P-256 digital signature for authenticated commands.
 *
 * IEC 62056-8-3 Security Suite 1: commands from the head-end system
 * to the meter (disconnect relay, tariff changes, firmware updates)
 * are signed with the head-end's ECDSA P-256 key. The meter verifies
 * the signature before executing the command.
 *
 * Source: GuruxDLMS.c development/src/gxEcdsa.c gxEcdsa_Sign()
 */
int dlms_sign_command(
    gxEccKeyPair *signing_key,      /* head-end ECDSA P-256 private key */
    gxByteBuffer *command_data,     /* DLMS APDU to sign */
    gxByteBuffer *signature)        /* output: 64-byte P-256 ECDSA signature (r||s) */
{
	/*
	 * ECDSA P-256 signature.
	 * The signing_key->publicKey is burned into the meter's secure storage
	 * at manufacture. Commands arriving with a valid signature are executed
	 * with full meter authority (disconnect power, update firmware, etc.).
	 *
	 * A CRQC recovering the head-end ECDSA private key from its public key
	 * (which is stored in every meter in the deployment) can sign arbitrary
	 * commands to every meter: disconnect power to every address on the grid,
	 * corrupt tariff tables, or push malicious firmware.
	 */
	return gxEcdsa_Sign(signing_key, command_data->data,
	                    command_data->size, signature);
}

/*
 * Meter certificate structure (IEC 62056-8-3 §7.2)
 * Each meter has an X.509 certificate containing its ECDSA P-256 public key,
 * issued by the utility's metering CA.
 */
typedef struct {
	uint8_t  system_title[8];          /* meter identifier (DLMS logical name) */
	uint8_t  certificate_type;         /* 0=digital signature, 1=key agreement */
	uint8_t  entity_type;              /* 0=server (meter), 1=client (head-end) */
	gxByteBuffer certificate;          /* DER-encoded X.509 certificate, P-256 key */
} dlmsCertificateInfo;

/*
 * Scale note:
 *
 * The EU Electricity Directive mandates 80% smart meter penetration by 2020.
 * UK: 35 million smart meters (SMETS2, IEC 62056 Security Suite 1)
 * Germany: 53 million meters in rollout (BSI mandated, Security Suite 1)
 * Italy: 35 million Enel/Enel X meters
 * Spain, France, Netherlands: comparable deployments
 *
 * P-256 and P-384 are both vulnerable to Shor's algorithm.
 * IEC 62056 Security Suite 3 with PQC does not exist.
 * The IEC TC57 WG14 (responsible for IEC 62056) has no PQC work item.
 *
 * Attacking the head-end signing key affects every meter in the deployment —
 * a single key compromise can forge commands to millions of meters.
 * For large utilities, that means the ability to disconnect power to millions
 * of homes simultaneously via forged relay disconnect commands.
 */
