/*
 * pos_contactless_txn.c
 *
 * EMV contactless purchase transaction orchestration from the POS
 * kernel side. Sits on top of the ICC command layer and below the
 * acquirer's authorization host dispatcher.  The RSA primitives it
 * calls (SDA / DDA / CDA offline authentication) live in
 * `emv_rsa_card_auth.c`.
 *
 * Deployed in every EMV Level-2 certified kernel on Earth:
 *   - Verifone Engage, Ingenico Axium, PAX A-series, Clover terminals
 *   - Chase Paymentech / First Data / Fiserv / Worldpay / Adyen / Square
 *     white-label payment apps
 *   - ATM kernels from NCR, Diebold Nixdorf, GRG Banking, Hyosung
 *   - Transit closed-loop readers (NYC OMNY, London contactless,
 *     Singapore SimplyGo) running EMV co-badged schemes
 *
 * Covers all eight EMV kernels (Visa VCPS, Mastercard PayPass M/Chip,
 * Amex ExpressPay, Discover D-PAS, UnionPay QuickPass, JCB J/Speedy,
 * Interac Flash, RuPay) — all of which depend on the RSA-based offline
 * card authentication covered here.
 */

#include <stdint.h>
#include <string.h>
#include "emv_kernel.h"
#include "emv_ca_keys.h"


int
pos_run_contactless(struct emv_kernel *k, struct emv_txn *t)
{
    /* 1.  PPSE SELECT + candidate list + application selection. */
    if (emv_select_ppse(k)          != 0) return EMV_DECLINE;
    if (emv_choose_app(k, t)        != 0) return EMV_DECLINE;

    /* 2.  GET PROCESSING OPTIONS → read AFL, read records. Card
     *     returns its CA public-key index + issuer public-key
     *     certificate + ICC public-key certificate, all RSA-signed
     *     under the scheme's CAPK. */
    if (emv_gpo(k, t)               != 0) return EMV_DECLINE;
    if (emv_read_records(k, t)      != 0) return EMV_DECLINE;

    /* 3.  Offline data authentication (ODA).  Preferred order per
     *     EMV Book 3: CDA > DDA > SDA > none.
     *     CAPK is the scheme-level RSA public key (Visa, Mastercard,
     *     JCB, etc., RSA-1152/1408/1984/2048) loaded into the kernel
     *     at L2 certification time and refreshed via acquirer config
     *     pushes. */
    const struct emv_capk *capk = emv_lookup_capk(
        t->rid, t->capk_index);
    if (!capk) { t->tvr |= EMV_TVR_ODA_NOT_PERFORMED; }
    else {
        int oda = emv_oda_cda(k, t, capk);             /* CDA */
        if (oda == EMV_UNSUPPORTED)
            oda = emv_oda_dda(k, t, capk);             /* DDA */
        if (oda == EMV_UNSUPPORTED)
            oda = emv_oda_sda(k, t, capk);             /* SDA */
        if (oda != 0) t->tvr |= EMV_TVR_ICC_DATA_MISSING;
    }

    /* 4.  Cardholder verification — for contactless under CVM limit
     *     this is no-CVM; above CVM limit the kernel prompts for
     *     device/PIN. */
    emv_run_cvm(k, t);

    /* 5.  Terminal risk management + terminal action analysis. */
    emv_trm(k, t);
    emv_taa(k, t);

    /* 6.  GENERATE AC (1st).  Under CDA the card returns an SDAD
     *     (Signed Dynamic Application Data) RSA-signed over the
     *     TC/ARQC + transaction data — kernel verifies it with the
     *     ICC RSA public key recovered in step 3 before accepting
     *     offline. */
    if (emv_generate_ac_first(k, t) != 0) return EMV_DECLINE;

    /* 7.  Online authorization (if ARQC requested).  The ARQC is a
     *     symmetric-crypto MAC under the issuer master key; RSA
     *     doesn't participate here.  Issuer authentication on return
     *     is also symmetric. */
    if (t->ac_type == EMV_ARQC) {
        emv_online_auth(k, t);
        emv_generate_ac_second(k, t);
    }

    /* 8.  Post-issuance scripts, velocity counters, done. */
    return t->outcome;
}


/* If RSA is broken, an attacker can (a) fabricate counterfeit EMV
 * cards whose ICC/Issuer cert chain re-checks against the scheme
 * CAPK — passing DDA/CDA offline approval at contactless limits with
 * no network path; (b) at the scheme-CA level, mint an entire
 * counterfeit issuer BIN range. Transit systems (tapping in millions
 * of daily fares against an offline-risk model) are the most exposed;
 * national-scale EMV fraud losses would jump by orders of magnitude
 * overnight. */
