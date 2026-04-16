/*
 * release_verify_chain.c
 *
 * APT (Advanced Package Tool) InRelease / Release.gpg signature
 * verification chain for Debian, Ubuntu, Raspbian, and every
 * derivative. This is the code path in apt-pkg that decides
 * whether `apt update && apt install <pkg>` trusts the package
 * index and proceeds to download .deb files.
 *
 * The trust anchor is the archive signing key:
 *   - Debian: RSA-4096 (ftp-master.debian.org)
 *   - Ubuntu: RSA-4096 (archive.ubuntu.com)
 *   - Third-party repos (Docker, Google, NVIDIA, NodeSource):
 *     RSA-2048/4096, imported via apt-key / signed-by
 *
 * A factored archive key allows an attacker to forge InRelease,
 * substitute Packages index hashes, and deliver malicious .deb
 * packages to every system running `apt update`.
 */

#include <stdint.h>
#include <string.h>
#include "apt.h"

extern const uint8_t ARCHIVE_SIGNING_PUB[];     /* RSA-4096     */
extern size_t ARCHIVE_SIGNING_PUB_LEN;

/* InRelease is a clearsigned GPG message:
 *   -----BEGIN PGP SIGNED MESSAGE-----
 *   Hash: SHA256
 *   <Release metadata: Date, Suite, Components, SHA256 hashes
 *    of every Packages/Sources/Contents file>
 *   -----BEGIN PGP SIGNATURE-----
 *   <detached or inline PGP sig>
 *   -----END PGP SIGNATURE-----
 */

struct inrelease {
    uint8_t  signed_text[65536];
    size_t   signed_text_len;
    uint8_t  sig[512];                 /* PGP sig packet         */
    size_t   sig_len;
    /* Extracted Packages file hashes: */
    struct {
        char    path[128];             /* "main/binary-amd64/Packages" */
        uint8_t sha256[32];
        uint64_t size;
    } files[256];
    uint16_t n_files;
};

int apt_verify_inrelease(const struct inrelease *r)
{
    /* (1) Parse the PGP signature packet: v4 sig, type 0x01
     * (text) or 0x00 (binary), pubkey algo 1 (RSA), hash
     * algo 8 (SHA-256). */
    uint8_t h[32];
    sha256_pgp_text(r->signed_text, r->signed_text_len, h);

    /* (2) Verify against archive signing key in the system
     * trust ring (/etc/apt/trusted.gpg.d/ or /usr/share/
     * keyrings/). */
    if (pgp_rsa_verify_sha256(
            ARCHIVE_SIGNING_PUB, ARCHIVE_SIGNING_PUB_LEN,
            h, 32, r->sig, r->sig_len))
        return APT_SIG_FAIL;

    /* (3) Check Date + Valid-Until for replay protection. */
    if (inrelease_is_stale(r->signed_text, r->signed_text_len))
        return APT_STALE;

    /* (4) Store verified file hashes for subsequent package
     * downloads. Every Packages.gz / Packages.xz is integrity-
     * checked against these hashes. */
    for (int i = 0; i < r->n_files; ++i)
        apt_cache_file_hash(r->files[i].path,
                            r->files[i].sha256,
                            r->files[i].size);
    return APT_OK;
}

/* After InRelease validation, apt downloads Packages index,
 * verifies its SHA-256 against the InRelease-committed hash,
 * then downloads each .deb whose SHA-256 is in Packages.
 * No per-package signing — trust is entirely delegated to
 * the archive signing key through InRelease. */

/* ---- Supply-chain attack on factored archive key ----------
 *  1. Forge an InRelease for any suite (stable, jammy, etc.)
 *     with modified SHA-256 for Packages.gz.
 *  2. Forge Packages.gz with a trojanized .deb entry
 *     (e.g. replace openssh-server with a backdoored one).
 *  3. Host on a mirror or MitM the APT HTTP connection
 *     (most mirrors are HTTP, not HTTPS — APT relies on
 *     GPG, not TLS, for integrity).
 *  4. `apt update` pulls the forged InRelease — GPG check
 *     passes. `apt upgrade` installs the trojanized .deb.
 *
 *  Blast radius: ~100M Debian/Ubuntu servers and desktops.
 *  Every CI/CD pipeline that runs `apt-get install`. Every
 *  Docker image that starts with `FROM ubuntu:...`.
 *
 *  Recovery: Debian/Ubuntu rotate archive key; every apt
 *  trust store must be updated. The update mechanism itself
 *  (apt install debian-archive-keyring) depends on the
 *  broken archive key — bootstrap paradox.
 * --------------------------------------------------------- */
