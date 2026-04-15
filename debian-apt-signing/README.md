# debian-apt-signing — RSA-4096 in Debian/Ubuntu APT repository signing (600M+ systems)

**Repository:** apt (Debian apt project); debian-archive-keyring  
**Industry:** Linux distribution — desktops, servers, cloud, embedded, IoT  
**Algorithm:** RSA-4096 (Debian 12/Ubuntu 24.04 current signing keys)  
**PQC migration plan:** None — Debian is experimenting with Ed25519 for some keys but production signing keys remain RSA-4096; no Debian Developer discussion on ML-DSA signing keys has reached consensus; Ubuntu follows Debian's lead

## What it does

APT (Debian/Ubuntu package manager) authenticates repositories by verifying a GPG
signature on the `InRelease` file at the root of every repository. This is a cleartext
GPG signature over the `Release` file which contains SHA-256 hashes of every package
index. The chain is: `InRelease` RSA signature → `Release` → `Packages.gz` hashes →
individual `.deb` hashes. Everything hangs on the RSA signature.

The Debian stable archive signing key is RSA-4096. It's in every Debian installation
at `/usr/share/keyrings/debian-archive-keyring.gpg` and publicly downloadable at
`ftp-master.debian.org/keys.html`. Ubuntu has its own RSA-4096 archive key in every
Ubuntu installation, also publicly available.

Scale:
- Debian: ~500M installations (VMs, servers, desktops, Raspberry Pi, network appliances)
- Ubuntu: ~100M+ cloud instances (AWS, GCP, Azure all default to Ubuntu base images)
- Derivatives: Raspbian, Kali, Tails, Parrot, Linux Mint, Pop!_OS, etc.
- Essentially every `apt-get install` on earth trusts one of these RSA-4096 keys

## Why it's stuck

- GPG-based APT signing has been the standard since 2005. Changing the algorithm
  requires updating apt, gpgv, the signing infrastructure, and distributing new
  keys to all existing installations simultaneously.
- Debian 12 (Bookworm) has been experimenting with Ed25519 for some secondary keys
  but the primary archive signing key remains RSA-4096. There is no Debian Developers
  discussion that has reached consensus on a PQC migration path.
- The `debian-archive-keyring` package would need to be updated to add PQC keys,
  but that package update itself is signed with the existing RSA-4096 key — so any
  transition needs to chain from RSA trust.
- Ubuntu's signing infrastructure is separate from Debian's. Both would need to
  migrate simultaneously to avoid divergence in the derivative ecosystem.

## impact

apt repository signing is the authentication layer for literally every package
installed on hundreds of millions of linux systems. the RSA key is the entire chain.

- the Debian RSA-4096 public key is at ftp-master.debian.org/keys.html and on every
  Debian system. factor it. sign a forged InRelease for a mirror. any system that
  updates through a MITM'd network path (corporate proxy, poisoned CDN, malicious
  mirror selected by apt's mirror rotation) will get your packages, accept them,
  install them. no error. no warning. apt says "installed."
- the attack is more powerful than SolarWinds because it doesn't target a specific
  software vendor. it targets the repository metadata. you don't need to know what
  packages the target will install — you forge the whole package index, and every
  `apt-get install` from that repo is yours.
- AWS, GCP, and Azure cloud instances use Ubuntu by default. they all run automatic
  security updates (`unattended-upgrades`). a forged apt mirror update would propagate
  to cloud instances automatically, overnight, everywhere.
- Raspberry Pi OS (Raspbian) is Debian-based. ~50M Raspberry Pi devices. many run
  in industrial, educational, and research settings. same attack chain.
- Kali Linux uses Debian repos. security researchers update their Kali boxes. this
  is notably ironic.

## Code

`debian_apt_rsa.sh` — `apt_verify_release()` (gpgv RSA-4096 InRelease verification),
`apt_sign_release()` (gpg --clearsign with Debian key ID), `build_malicious_release()`
(forge InRelease with factored RSA-4096 private key, build complete evil repo),
`show_apt_key_info()` (list RSA-4096 keys from system keyrings). Mirror attack scenario
and deployment scale in comments.
