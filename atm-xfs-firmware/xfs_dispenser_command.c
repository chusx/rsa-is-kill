/*
 * xfs_dispenser_command.c
 *
 * CEN/XFS (eXtensions for Financial Services) dispenser command
 * path: host application -> XFS SP (Service Provider) ->
 * dispenser MCU. Signed firmware and signed dispense commands
 * are required under PCI-DSS v4.0 §6.5 for ATM/kiosk.
 *
 * Vendors: NCR (SelfServ), Diebold Nixdorf (CS 5xxx/DN Series),
 * Hyosung (MoniMax), GRG Banking.
 *
 * An attacker with a factored dispenser OEM signing key can
 * inject firmware or forge dispense commands — "jackpotting"
 * at scale without physical manipulation.
 */

#include <stdint.h>
#include <string.h>
#include "xfs.h"

extern const uint8_t ATM_OEM_FW_ROOT_PUB[384];

struct dispense_cmd {
    char       atm_id[16];
    uint32_t   txn_seq;
    uint32_t   amount_cents;
    uint8_t    denomination_map[8];    /* bills per cassette      */
    uint64_t   host_ts_ns;
    uint8_t    host_cert[2048]; size_t host_cert_len;
    uint8_t    sig[384];
};

int dispenser_execute(const struct dispense_cmd *c)
{
    if (c->txn_seq <= nvram_last_txn(c->atm_id)) return XFS_REPLAY;
    if (x509_chain_verify(c->host_cert, c->host_cert_len,
            ATM_OEM_FW_ROOT_PUB, sizeof ATM_OEM_FW_ROOT_PUB))
        return XFS_CHAIN;
    uint8_t h[32];
    sha256_of(c, offsetof(struct dispense_cmd, host_cert), h);
    if (verify_with_cert(c->host_cert, c->host_cert_len,
                         h, c->sig, sizeof c->sig))
        return XFS_SIG;

    nvram_txn_bump(c->atm_id, c->txn_seq);
    return motor_dispense(c->denomination_map);
}

/* ---- Jackpotting at fleet scale ---------------------------
 *  ATM_OEM_FW_ROOT factored: forge dispense commands to every
 *  ATM running that OEM's XFS stack. Remote jackpotting
 *  without physical access; mules collect at the fascia.
 *  Also: forge firmware to disable shutter/alarm/jitter/EPP-
 *  PIN verification. Recovery: OEM rotates FW signing key +
 *  every dispenser MCU re-provisioned (truck-roll per ATM;
 *  ~400k ATMs per major OEM in the US alone).
 * --------------------------------------------------------- */
