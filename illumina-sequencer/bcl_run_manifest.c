/*
 * bcl_run_manifest.c
 *
 * Illumina NovaSeq 6000 / NextSeq 2000 / MiSeq run manifest
 * and recipe signing. Sequencer recipes (chemistry kits,
 * flow-cell configs, base-calling models) are signed by
 * Illumina before installation on the sequencer; this prevents
 * unauthorized recipe modifications that could alter basecall
 * accuracy or run parameters.
 *
 * A factored Illumina recipe-signing key allows an attacker
 * to push modified recipes that silently corrupt sequencing
 * data — affecting clinical genomics (oncology panels,
 * pharmacogenomics), forensic DNA (CODIS), and pathogen
 * surveillance (CDC AMD).
 */

#include <stdint.h>
#include <string.h>
#include "illumina.h"

extern const uint8_t ILLUMINA_RECIPE_ROOT_PUB[384];

struct run_recipe {
    char       instrument_model[16];   /* "NovaSeq6000"           */
    char       chemistry[16];          /* "SPv1.5", "v3.1"        */
    uint32_t   recipe_version;
    uint32_t   read_length_r1;
    uint32_t   read_length_r2;
    uint32_t   index_length_i1;
    uint32_t   index_length_i2;
    uint8_t    basecall_model_sha256[32];
    uint8_t    sig[384];
};

int sequencer_load_recipe(const struct run_recipe *r)
{
    if (r->recipe_version <= nvram_recipe_version())
        return SEQ_ROLLBACK;

    uint8_t h[32];
    sha256_of(r, offsetof(struct run_recipe, sig), h);
    if (rsa_pss_verify_sha256(ILLUMINA_RECIPE_ROOT_PUB, 384,
            (uint8_t[]){1,0,1}, 3, h, 32,
            r->sig, sizeof r->sig))
        return SEQ_SIG;

    return sequencer_install_recipe(r);
}

/* ---- Clinical / forensic / public-health impact -----------
 *  ILLUMINA_RECIPE_ROOT factored:
 *    Forge recipe with modified basecall model -> systematic
 *    miscalls (e.g. +1% error rate at specific loci). In a
 *    clinical oncology panel: missed variants -> wrong Tx
 *    decision. In forensic CODIS: false exclusion or
 *    inclusion at STR loci. In CDC pathogen surveillance:
 *    masked outbreak strain.
 *    No downstream bioinformatician would detect the error
 *    because the recipe was "Illumina-signed."
 * --------------------------------------------------------- */
