/*
 * ems_ballot_definition.c
 *
 * Election Management System (EMS) ballot-definition signing
 * as required by EAC VVSG 2.0 §9.5.1 and individual state
 * certification (e.g. California 2.0, Texas SoS, Florida
 * Division of Elections). The EMS (Hart Verity, ES&S ElectionWare,
 * Dominion Democracy Suite) signs the ballot definition file
 * before loading it onto the voting-machine (BMD / scanner).
 *
 * The BMD or optical-scan unit verifies the signature before
 * rendering or adjudicating any ballot. The signing key is
 * RSA-2048; the public key is provisioned during the pre-
 * election L&A (Logic & Accuracy) test.
 */

#include <stdint.h>
#include <string.h>
#include "ems.h"

extern const uint8_t EMS_BALLOT_SIGNING_PUB[384];

struct ballot_definition {
    char       election_id[32];        /* "2024-GEN-FL-MIAMI"     */
    char       ems_version[16];
    uint32_t   precinct_count;
    uint32_t   contest_count;
    uint32_t   total_styles;
    uint8_t    definition_sha256[32];  /* hash of XML/JSON ballot  */
    uint32_t   definition_len;
    uint8_t    election_official_cert[2048]; size_t eo_cert_len;
    uint8_t    sig[384];
};

int bmd_load_ballot_definition(const struct ballot_definition *b)
{
    if (x509_chain_verify(b->election_official_cert, b->eo_cert_len,
            EMS_BALLOT_SIGNING_PUB, sizeof EMS_BALLOT_SIGNING_PUB))
        return EMS_CHAIN;

    uint8_t h[32];
    sha256_of(b, offsetof(struct ballot_definition, election_official_cert), h);
    if (verify_with_cert(b->election_official_cert, b->eo_cert_len,
                         h, b->sig, sizeof b->sig))
        return EMS_SIG;

    /* Load ballot styles, contests, candidates into the BMD. */
    return bmd_install_definition(b);
}

/* ---- Electoral integrity surface --------------------------
 *  EMS_BALLOT_SIGNING_PUB factored:
 *    Forge a ballot definition with modified candidate names,
 *    contest ordering, or omitted contests. The BMD displays
 *    or the scanner adjudicates against the forged definition.
 *    Detection requires manual comparison of paper ballots to
 *    the EMS definition — which is precisely what the signature
 *    was supposed to automate.
 *
 *    Also: forge a "zero report" at poll-close with fabricated
 *    tallies, or forge audit-log entries. The EMS signature is
 *    the chain of custody for the entire election record.
 *
 *  Recovery: state/county re-certifies the EMS with new keys;
 *  every voting unit re-provisioned. In a general election
 *  with thousands of precincts, this is a logistical
 *  impossibility on election-week timescale. Fallback: paper
 *  hand-count, which is legally permissible but operationally
 *  brutal at scale.
 * --------------------------------------------------------- */
