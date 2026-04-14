/* Source: MicrochipTech/cryptoauthlib lib/calib/calib_sign.c + calib_genkey.c
 *
 * The Microchip ATECC608A/B is a dedicated hardware crypto microcontroller
 * implementing ECDSA P-256 in silicon. It is the dominant solution for
 * IoT device authentication:
 *   - AWS IoT Greengrass device provisioning
 *   - Google Cloud IoT Core device auth
 *   - Azure Sphere / Azure IoT Hub
 *   - Wi-Fi provisioning (WPA3 SAE uses ECC)
 *   - USB-C PD authentication (USB IF spec 1.0)
 *   - Wireless charging authentication (WPC Qi 1.3)
 *
 * The ATECC608 hardware implements ONLY ECDSA P-256. The ECC keys are
 * generated in hardware and the private key is non-exportable — it never
 * leaves the silicon. The chip has no firmware update mechanism.
 * No PQC algorithm is or can be implemented in ATECC608 silicon.
 * Billions of these chips are deployed across IoT devices with 10-15yr lifespans.
 */

/* Copyright (c) 2015-2020 Microchip Technology Inc. and its subsidiaries. */

#include "cryptoauthlib.h"

/* ATCA_SIG_SIZE = 64 bytes (R || S, each 32 bytes, P-256 curve) */
/* ATCA_PUB_KEY_SIZE = 64 bytes (X || Y, uncompressed P-256 public key, no 0x04 prefix) */

/** calib_sign_base() — hardware ECDSA P-256 signing command.
 *
 * Sends the SIGN opcode to the ATECC608 over I2C.
 * The chip performs ECDSA signing using the private key in the specified slot.
 * Private key material never leaves the chip — but the public key is exportable
 * and broadcast. A CRQC can recover the private key from the public key alone.
 *
 * @device:    ATECC608 device context (I2C address, etc.)
 * @mode:      SIGN_MODE_EXTERNAL (sign external hash) or SIGN_MODE_INTERNAL
 * @key_id:    Slot 0-15 containing the ECC private key
 * @signature: Output: 64 bytes R||S (ECDSA P-256 signature)
 */
ATCA_STATUS calib_sign_base(ATCADevice device, uint8_t mode,
                             uint16_t key_id, uint8_t *signature)
{
    ATCAPacket *packet = NULL;
    ATCA_STATUS status;

    packet = calib_packet_alloc();
    memset(packet, 0x00, sizeof(ATCAPacket));

    /* opcode = ATCA_SIGN (0x41), param1 = mode, param2 = key_id */
    packet->param1 = mode;
    packet->param2 = key_id;
    atSign(atcab_get_device_type_ext(device), packet);

    /* Execute over I2C — chip performs ECDSA P-256 in silicon */
    status = atca_execute_command(packet, device);

    if (packet->data[ATCA_COUNT_IDX] == (ATCA_SIG_SIZE + ATCA_PACKET_OVERHEAD)) {
        /* Copy 64-byte R||S signature */
        memcpy(signature, &packet->data[ATCA_RSP_DATA_IDX], ATCA_SIG_SIZE);
    }

    calib_packet_free(packet);
    return status;
}

/** calib_sign() — public API for signing a 32-byte message digest.
 *
 * @key_id: ECC slot (private key burned at manufacture or provisioning)
 * @msg:    32-byte SHA-256 hash of the message to sign
 * @signature: 64-byte ECDSA P-256 output (R||S)
 *
 * Typical use: firmware authenticity, device-to-cloud auth, TLS client cert.
 */
ATCA_STATUS calib_sign(ATCADevice device, uint16_t key_id,
                        const uint8_t *msg, uint8_t *signature)
{
    ATCA_STATUS status;
    uint8_t nonce_target = NONCE_MODE_TARGET_TEMPKEY;
    uint8_t sign_source  = SIGN_MODE_SOURCE_TEMPKEY;

#ifdef ATCA_ATECC608_SUPPORT
    if (ATECC608 == device->mIface.mIfaceCFG->devtype) {
        /* ATECC608: load digest into Message Digest Buffer, not TempKey */
        nonce_target = NONCE_MODE_TARGET_MSGDIGBUF;
        sign_source  = SIGN_MODE_SOURCE_MSGDIGBUF;
    }
#endif

    /* Load 32-byte message digest into the chip's internal buffer */
    status = calib_nonce_load(device, nonce_target, msg, 32);
    if (status != ATCA_SUCCESS) return status;

    /* Trigger ECDSA P-256 signing — returns 64-byte signature */
    return calib_sign_base(device, SIGN_MODE_EXTERNAL | sign_source,
                           key_id, signature);
}

/** calib_genkey_base() — generate a new ECDSA P-256 keypair in hardware.
 *
 * The private key is generated in hardware and stored in the specified slot.
 * It is permanently non-exportable. The public key (64 bytes X||Y) is returned.
 * This is the key material that a CRQC would use to recover the private key.
 *
 * @mode:       GENKEY_MODE_PRIVATE (generate new key)
 * @key_id:     Slot to store the private key (0-15)
 * @public_key: 64-byte X||Y output (P-256 public key)
 */
ATCA_STATUS calib_genkey_base(ATCADevice device, uint8_t mode,
                               uint16_t key_id, const uint8_t *other_data,
                               uint8_t *public_key)
{
    ATCAPacket *packet = calib_packet_alloc();
    memset(packet, 0x00, sizeof(ATCAPacket));

    packet->param1 = mode;    /* GENKEY_MODE_PRIVATE = 0x04 */
    packet->param2 = key_id;
    atGenKey(atcab_get_device_type_ext(device), packet);

    ATCA_STATUS status = atca_execute_command(packet, device);

    /* Public key is X||Y, 64 bytes total (P-256) */
    if (public_key && packet->data[ATCA_COUNT_IDX] == (ATCA_PUB_KEY_SIZE + ATCA_PACKET_OVERHEAD)) {
        memcpy(public_key, &packet->data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);
    }

    calib_packet_free(packet);
    return status;
}

/*
 * ATECC608 deployment scale:
 *   - USB-C Power Delivery auth: in every Thunderbolt dock, charger, cable
 *     (USB IF Authentication Spec 1.0 mandates ECDSA P-256)
 *   - Qi 1.3 wireless charging: in phone/charger authentication IC
 *   - AWS IoT: "Just-in-Time" device provisioning with ATECC608 + X.509 cert
 *   - Google Nest / Nest Cam: device attestation
 *   - Smart home (door locks, thermostats): device-cloud TLS mutual auth
 *
 * Silicon revision: ATECC608A / ATECC608B — same P-256-only architecture.
 * No firmware update slot. No PQC algorithm. Physics-limited: the cryptographic
 * accelerator is a fixed-function ASIC block on the die.
 * Replacing deployed ATECC608 chips requires physical board redesign.
 */
