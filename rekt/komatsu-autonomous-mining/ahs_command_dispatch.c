/*
 * ahs_command_dispatch.c
 *
 * Komatsu FrontRunner AHS (Autonomous Haulage System) /
 * Caterpillar Command for Hauling / Hitachi AHS signed
 * command path from the mine dispatch server to the
 * autonomous haul truck (Komatsu 930E, CAT 797F).
 *
 * The dispatch server issues signed route assignments,
 * speed limits, and emergency stop commands. The truck's
 * on-board controller verifies against the mine-site OEM
 * PKI before executing. ~1000 autonomous haul trucks
 * operate in mining sites globally (Pilbara, Atacama,
 * Chuquicamata, Carlin, Cerrejón).
 */

#include <stdint.h>
#include <string.h>
#include "ahs.h"

extern const uint8_t MINE_DISPATCH_ROOT_PUB[384];

enum ahs_cmd {
    AHS_ROUTE_ASSIGN  = 0x01,
    AHS_SPEED_LIMIT   = 0x02,
    AHS_E_STOP        = 0x80,
    AHS_FW_UPDATE     = 0x90,
};

struct ahs_command {
    char       mine_id[12];
    uint32_t   truck_id;
    uint32_t   cmd_seq;
    uint8_t    cmd;
    uint8_t    params[256];
    uint8_t    dispatch_cert[2048]; size_t dispatch_cert_len;
    uint8_t    sig[384];
};

int truck_accept_command(const struct ahs_command *c)
{
    if (c->cmd_seq <= nvram_last_seq(c->truck_id)) return AHS_REPLAY;
    if (x509_chain_verify(c->dispatch_cert, c->dispatch_cert_len,
            MINE_DISPATCH_ROOT_PUB, sizeof MINE_DISPATCH_ROOT_PUB))
        return AHS_CHAIN;
    uint8_t h[32];
    sha256_of(c, offsetof(struct ahs_command, dispatch_cert), h);
    if (verify_with_cert(c->dispatch_cert, c->dispatch_cert_len,
                         h, c->sig, sizeof c->sig))
        return AHS_SIG;
    nvram_seq_bump(c->truck_id, c->cmd_seq);
    switch (c->cmd) {
    case AHS_ROUTE_ASSIGN: return route_load(c->params);
    case AHS_SPEED_LIMIT:  return speed_cap(c->params);
    case AHS_E_STOP:       return emergency_brake();
    case AHS_FW_UPDATE:    return fw_stage(c->params);
    }
    return AHS_BAD_CMD;
}

/* ---- 400-ton truck on forged route -------------------------
 *  MINE_DISPATCH_ROOT factored: route a 400-ton haul truck
 *  off the pit road -> collapse of pit wall, truck rollover,
 *  personnel risk. Or: disable E-STOP across a fleet, then
 *  trigger a geofence breach. Recovery: OEM + mine operator
 *  re-provision every truck at the site.
 * --------------------------------------------------------- */
