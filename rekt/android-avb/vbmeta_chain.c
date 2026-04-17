/*
 * vbmeta_chain.c
 *
 * Android Verified Boot 2.0 vbmeta descriptor walker.
 * The top-level vbmeta image is signed by the device's
 * OEM-provisioned RSA public key (stored in RPMB / eFuse);
 * it enumerates descriptors that either contain a hash of
 * another partition, or chain to a further vbmeta image
 * (used for boot / system / vendor / product).
 *
 * Ref: external/avb/libavb/avb_slot_verify.c upstream.
 *      Google Pixel 9 uses RSA-4096 vbmeta root; Samsung
 *      mid-range and Xiaomi typically RSA-2048.
 */

#include <stdint.h>
#include <string.h>
#include "avb.h"

#define AVB_MAGIC              "AVB0"
#define AVB_DESC_HASH          2
#define AVB_DESC_CHAIN         4
#define AVB_DESC_HASHTREE      1
#define AVB_DESC_PROP          0

struct avb_vbmeta_header {
    char      magic[4];                 /* "AVB0" */
    uint32_t  req_libavb_major;
    uint32_t  req_libavb_minor;
    uint64_t  auth_data_block_size;
    uint64_t  aux_data_block_size;
    uint32_t  algorithm_type;           /* 1=SHA256+RSA2048 ... */
    uint64_t  hash_offset;
    uint64_t  hash_size;
    uint64_t  signature_offset;
    uint64_t  signature_size;
    uint64_t  public_key_offset;
    uint64_t  public_key_size;
    uint64_t  public_key_metadata_offset;
    uint64_t  public_key_metadata_size;
    uint64_t  descriptors_offset;
    uint64_t  descriptors_size;
    uint64_t  rollback_index;
    uint32_t  flags;
    uint32_t  rollback_index_location;
    uint8_t   release_string[48];
    /* ... plus 80 bytes reserved */
};

/* Chain descriptor — delegates verification of a named partition
 * to a child vbmeta that is itself signed with a different key.
 * This is how Pixel ships per-partition key separation. */
struct avb_chain_desc {
    uint32_t  tag;                      /* AVB_DESC_CHAIN */
    uint32_t  num_bytes_following;
    uint32_t  rollback_index_location;
    uint32_t  partition_name_len;
    uint32_t  public_key_len;
    uint32_t  flags;
    /* followed by partition_name, public_key */
};

int avb_slot_verify(const char *slot_suffix)
{
    const uint8_t *vbmeta = boot_partition_read("vbmeta", slot_suffix);
    const struct avb_vbmeta_header *h = (const void *)vbmeta;

    if (memcmp(h->magic, AVB_MAGIC, 4)) return AVB_ERR_MAGIC;

    /* 1. Check the embedded RSA public key against the
     * device-provisioned OEM root (burned into RPMB slot 0). */
    uint8_t rpmb_root[2048/8];
    if (rpmb_read_auth(RPMB_SLOT_AVB_ROOT, rpmb_root, sizeof rpmb_root))
        return AVB_ERR_RPMB;
    if (memcmp(vbmeta + h->public_key_offset,
               rpmb_root, h->public_key_size))
        return AVB_ERR_KEY_MISMATCH;

    /* 2. Rollback-index check — the fused counter for this
     * location must be <= h->rollback_index. */
    uint64_t fused;
    if (fuse_read_rollback(h->rollback_index_location, &fused))
        return AVB_ERR_FUSE;
    if (h->rollback_index < fused) return AVB_ERR_ROLLBACK;

    /* 3. Verify RSA-PKCS#1 v1.5 (SHA-256) signature over
     * auth_data_block_size || aux_data_block_size. */
    if (rsa_pkcs1v15_verify(
            vbmeta + h->public_key_offset, h->public_key_size,
            vbmeta, h->auth_data_block_size + h->aux_data_block_size,
            vbmeta + h->signature_offset, h->signature_size))
        return AVB_ERR_SIG;

    /* 4. Walk descriptors. Every HASH descriptor gets checked
     * against the partition bytes; every CHAIN descriptor
     * recurses into another vbmeta image. */
    const uint8_t *d = vbmeta + h->descriptors_offset;
    const uint8_t *d_end = d + h->descriptors_size;
    while (d < d_end) {
        uint32_t tag = read_be32(d);
        uint32_t nbytes = read_be32(d + 4);
        switch (tag) {
        case AVB_DESC_HASH:
            if (avb_check_hash_desc(d, nbytes, slot_suffix))
                return AVB_ERR_HASH;
            break;
        case AVB_DESC_CHAIN:
            if (avb_check_chain_desc(d, nbytes, slot_suffix))
                return AVB_ERR_CHAIN;
            break;
        }
        d += 8 + nbytes;
    }

    /* 5. On success, burn the fuse forward to the new
     * rollback index (monotonic, irreversible). */
    return fuse_write_rollback(h->rollback_index_location,
                               h->rollback_index);
}

/* ---- Breakage ------------------------------------------------
 *  Any AVB rollout signed by a factored RSA root is a golden
 *  image path: the bootloader sees a cryptographically valid
 *  vbmeta, the green-state attestation reports GREEN, and the
 *  user sees no warning.
 *
 *  A forged vbmeta with rollback_index = current + 1 will
 *  additionally burn the fuse forward, locking out later
 *  installation of the legitimate updated image on that
 *  device — persistence via monotonic counter.
 * -------------------------------------------------------------- */
