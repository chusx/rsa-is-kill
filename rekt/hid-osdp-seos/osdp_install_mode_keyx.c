/*
 * osdp_install_mode_keyx.c
 *
 * OSDP v2.2 Install-Mode initial key exchange + Secure Channel
 * bring-up between an access-control panel (Mercury LP4502,
 * Lenel NX, Software House iSTAR Ultra, Gallagher Controller 6000)
 * and an OSDP reader (HID Signo 20, iCLASS SE R10, Farpointe Delta).
 *
 * Runtime operations thereafter are AES-128-CMAC under the SCBK-D
 * derived here, but the *initial* SCBK-D install is RSA-wrapped,
 * so the trust bootstrap is an RSA operation.
 */

#include <stdint.h>
#include <string.h>
#include "osdp.h"
#include "rsa_oaep.h"
#include "aes_cmac.h"

/* Panel-side: the installer runs a one-shot Install Mode cycle per
 * reader. Reader presents its factory-installed RSA-2048 cert,
 * signed by the HID vendor CA (or by the system integrator's
 * customer CA for Lenel / Gallagher / S2 ecosystems). */

struct panel_state {
    uint8_t    reader_cert[1536];   /* RSA-2048 leaf */
    size_t     reader_cert_len;
    uint8_t    vendor_root[384];    /* RSA-3072 HID vendor root */
};

struct reader_state {
    uint32_t   priv_handle;         /* secure-element slot */
    uint8_t    reader_cert[1536];
    size_t     reader_cert_len;
    uint8_t    scbk_d[16];          /* derived session base-key */
};


/* ---- Phase 1: READER_CAPAS exchange & cert presentation ---- */

int panel_request_reader_ident(struct panel_state *p, int addr)
{
    /* osdp_POLL → osdp_ACK  (normal)
     *
     * Install-Mode differs: panel sends osdp_KEYSET followed by
     * CMD_MFG 0xF1 INSTALL_MODE_INIT which returns READER_CERT. */
    osdp_send_cmd_mfg(addr, OSDP_INSTALL_MODE_INIT);
    return osdp_recv_reader_cert(addr,
                                  p->reader_cert, &p->reader_cert_len);
}


/* ---- Phase 2: Panel generates + wraps SCBK-D to reader RSA pubkey --- */

int panel_install_scbk(struct panel_state *p, int addr,
                        uint8_t scbk_d[16])
{
    /* 1. Chain-verify reader cert to pinned vendor root. */
    uint8_t reader_pub_n[256]; size_t n_len;
    uint8_t reader_pub_e[4];   size_t e_len;
    if (x509_verify_and_extract_pub(
            p->reader_cert, p->reader_cert_len,
            p->vendor_root, sizeof p->vendor_root,
            reader_pub_n, sizeof reader_pub_n, &n_len,
            reader_pub_e, sizeof reader_pub_e, &e_len) != 0)
        return -1;

    /* 2. Generate fresh SCBK-D (Secure Channel Base Key, Detached). */
    rand_bytes(scbk_d, 16);

    /* 3. RSA-OAEP wrap and send via osdp_MFG INSTALL_MODE_KEY. */
    uint8_t wrapped[256]; size_t wrapped_len;
    if (rsa_oaep_wrap(reader_pub_n, n_len, reader_pub_e, e_len,
                       scbk_d, 16, wrapped, sizeof wrapped, &wrapped_len) != 0)
        return -1;

    return osdp_send_cmd_mfg_payload(addr, OSDP_INSTALL_MODE_KEY,
                                      wrapped, wrapped_len);
}


/* ---- Phase 3: Reader unwraps, installs, confirms --- */

int reader_ingest_install_key(struct reader_state *r,
                               const uint8_t *wrapped, size_t wrapped_len)
{
    uint8_t key[16]; size_t key_len;
    if (rsa_oaep_unwrap(r->priv_handle,
                         wrapped, wrapped_len,
                         key, 16, &key_len) != 0)
        return -1;
    if (key_len != 16) return -1;

    /* Store SCBK-D in tamper-responsive NVRAM */
    secure_nvram_write(NVRAM_SLOT_SCBK_D, key, 16);
    memcpy(r->scbk_d, key, 16);
    memset(key, 0, sizeof key);
    return 0;
}


/* ---- Phase 4: Secure Channel Session (SCS) operation ---- */

/* Every packet post-install is SCS-framed:
 *   - SCS_11/SCS_12 establishment MACs under SCBK-S (server) / SCBK-D
 *   - SCS_15/SCS_16/SCS_17/SCS_18 runtime data frames are AES-CBC
 *     encrypted + CMAC authenticated under session-specific keys
 *     derived from SCBK-D via the OSDP key-derivation function.
 * The symmetric crypto from here on is unaffected by RSA — but the
 * trust chain that put SCBK-D in both panel and reader in the first
 * place rests entirely on the RSA wrap above. */

int reader_send_card_read(struct reader_state *r,
                           const uint8_t *card_data, size_t len)
{
    uint8_t scs_frame[512]; size_t scs_len;
    osdp_scs_wrap(r->scbk_d, OSDP_CMD_RAW, card_data, len,
                   scs_frame, &scs_len);
    return osdp_uart_send(scs_frame, scs_len);
}


/* ---- Breakage ----
 *
 *   Factor the reader's RSA-2048 keypair:
 *     - Attacker captures the Install-Mode RSA-OAEP blob (plausible
 *       in any installation where the panel-to-reader run is tapped
 *       during commissioning), recovers SCBK-D, and subsequently
 *       forges card-reads into the panel and spoofs responses from
 *       the panel to the reader. The door opens on an attacker-
 *       chosen PACS decision.
 *
 *   Factor the HID (or customer-PKI) vendor root:
 *     - Attacker mints a reader cert with arbitrary parameters,
 *       passes chain validation on any panel keyed to that root,
 *       and receives a fresh SCBK-D for the target site. Rogue
 *       reader can then emit arbitrary "valid credential" frames
 *       to force door-open events.
 *
 *   Factor the reader / panel firmware-signing key:
 *     - Signed malicious firmware installable via the normal update
 *       channel. Fleet-wide tamper: every access event logged or
 *       silently allowed at attacker discretion.
 */
