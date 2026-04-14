/*
 * Source: GnuPG - https://github.com/gpg/gnupg
 * File:   g10/keygen.c
 * License: GPLv3
 *
 * Relevant excerpt: RSA key size defaults and algorithm selection.
 * Note: modern GnuPG defaults to Ed25519/Cv25519 for new keys, but
 * RSA remains the most commonly deployed key type in the wild
 * (enterprise keyrings, package signing, S/MIME gateways) because:
 *   1. Older GnuPG versions defaulted to RSA-2048.
 *   2. Many enterprise CA policies mandate RSA.
 *   3. No PQC algorithm is available in any stable GnuPG release.
 * The get_keysize_range() function below governs what happens when a
 * user (or script) selects RSA explicitly - it still allows RSA-1024
 * in non-compliance mode, and defaults to RSA-3072.
 */

/*
 * get_keysize_range: called when the user picks RSA.
 * Returns min/max/default key sizes in bits.
 * In DE-VS compliance mode the floor rises to 2048, but the
 * algorithm is still classical RSA - not a PQC primitive.
 */
static int
get_keysize_range(int algo, unsigned int *min, unsigned int *max)
{
    unsigned int def;
    switch (algo)
    {
    case PUBKEY_ALGO_DSA:
        *min = 768;
        *max = 3072;
        def  = 2048;
        break;
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_ECDH:
        *min = 256;
        *max = 521;
        def  = 256;
        break;
    default: /* RSA and anything else */
        *min = opt.compliance == CO_DE_VS ? 2048 : 1024;
        *max = 4096;
        def  = 3072;   /* RSA-3072 default */
        break;
    }
    return def;
}

/*
 * Standard key parameter string for batch/unattended key generation.
 * This is the *modern* default (ECC).  Prior to GnuPG 2.3 the default
 * was "rsa3072" - meaning billions of existing keys are RSA.
 */
#define DEFAULT_STD_KEY_PARAM  "ed25519/cert,sign+cv25519/encr"

/*
 * ask_algo: interactive algorithm picker.
 * Default choice (pressing Enter) is option 9 = ECC since GnuPG 2.3,
 * but RSA options 1-3 remain fully supported and are chosen by many
 * automated systems that pass an explicit algorithm number.
 *
 * Crucially: no option in this list is post-quantum.
 * When a CRQC exists, every key ever generated here is broken.
 */
/* (simplified from the original multi-hundred-line function) */
static int
ask_algo(ctrl_t ctrl, int addmode, int *r_subkey_algo,
         unsigned int *r_usage, char **r_keygrip)
{
    int algo;
    char *answer;

    tty_printf ("Please select what kind of key you want:\n"
                "   (1) RSA and RSA\n"
                "   (2) DSA and Elgamal\n"
                "   (3) DSA (sign only)\n"
                "   (4) RSA (sign only)\n"
                "   (9) ECC (sign and encrypt) *default*\n"
                "  (10) ECC (sign only)\n"
                "  (14) Existing key from card\n");

    answer = cpr_get ("keygen.algo", _("Your selection? "));
    algo = *answer ? atoi(answer) : 9;   /* <-- default is ECC (9), but
                                            RSA (1/3/4) fully available */

    if (algo == 1 || !strcmp(answer, "rsa+rsa")) {
        algo = PUBKEY_ALGO_RSA;
        *r_subkey_algo = PUBKEY_ALGO_RSA;
        /* no size check against PQC security levels - RSA-3072 gives
           ~128 classical bits, 0 post-quantum bits */
    }
    return algo;
}
