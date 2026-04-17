# rpm-gpg-signing — RSA-4096 in Red Hat / Fedora / CentOS package signing (500M+ systems)

**Repository:** rpm-software-management/rpm; Red Hat signing infrastructure 
**Industry:** Linux distribution package management — enterprise, cloud, embedded 
**Algorithm:** RSA-4096 (Red Hat / Fedora current signing keys); RSA-2048 (older keys still in use for RHEL 6/7) 

## What it does

Every package in RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, Oracle Linux, and SUSE
is signed with the distribution's GPG key before being published. When yum/dnf/zypper
installs a package, RPM verifies the RSA signature against the imported public key.
A failed signature causes installation refusal (unless explicitly overridden with
`--nogpgcheck`, which nobody should be doing on production systems).

The signing keys are RSA-4096 for current releases:
- RHEL 9 key: `199E2F91FD431D51` (RSA-4096, 2021)
- RHEL 8 key: `77E79ABE90E98ECE` (RSA-4096, 2019)
- Fedora 40 key: `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89` (RSA-4096)

These public keys ship in every OS installation at `/etc/pki/rpm-gpg/`, are published
at `access.redhat.com/security/team/key/`, and are in the keyservers. The public key
is on every RHEL system, every container base image, every cloud instance.

Also in scope: SUSE (openSUSE/SLES use similar GPG-signed RPMs), Oracle Linux,
and Amazon Linux (which uses RPM package format with RSA signing).

## Why it's stuck

- RPM's signature verification calls GnuPG or gpgme. GnuPG experimental ML-DSA
 support (based on libgcrypt with Dilithium) is not in any stable release. Even
 when it is, the RPM spec and tooling need to be updated to use new algorithm IDs.
- Red Hat's signing infrastructure is a dedicated air-gapped HSM environment.
 Key rollover requires updating the imported public key on every RHEL system —
 which means a system update or configuration management push. For systems without
 centralized management, this is manual.
- Older RHEL keys (RSA-2048, used for RHEL 6/7 packages still in use in long-tail
 enterprise environments) are even weaker and have no migration path because RHEL 6
 is end-of-life.
- Any non-RSA migration would need to be coordinated across Red Hat, Fedora, CentOS, Rocky,
 Alma, Oracle, SUSE, Amazon Linux simultaneously to avoid breaking package verification
 across the ecosystem.

## impact

every RHEL server in existence trusts the Red Hat RSA-4096 signing key. that's the entire
enterprise linux ecosystem. one key, 500 million systems.

- the Red Hat RSA-4096 public key is at `access.redhat.com/security/team/key/` and in
 `/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release` on every RHEL system. factor it.
 now you can sign any RPM that will be accepted by every RHEL 9 system with no warning.
 no supply chain breach needed. no red hat build server compromise needed. just math.
- the attack package can be anything: a kernel module, a modified ssh daemon, a backdoored
 openssl, a systemd unit that exfiltrates data. dnf installs it because it's signed by
 the Red Hat key and the gpg check passes.
- push the malicious package to any unofficial mirror, or serve it via a local yum repo.
 dnf's mirrorlist logic trusts package signatures more than mirror identity. a valid Red Hat
 signature overrides user suspicion about the mirror.
- for containers: all official Red Hat UBI (Universal Base Image) containers on quay.io
 and dockerhub pull from Red Hat repos. if you can sign packages for those repos, you
 can inject backdoored packages into every container build that `RUN dnf install` anything.
 that's essentially all enterprise containerized workloads.
- RHEL 6/7 have RSA-2048 keys with no support lifecycle. they're running in production in
 healthcare, finance, and government on systems that aren't getting updated. these are
 strictly lower barrier to attack than the RSA-4096 current keys.

## Code

`rpm_rsa_signing.sh` — `rpm_sign_package()` (rpmsign --addsign with RSA-4096 key ID),
`rpm_verify_signature()` (rpm -K, calls into gpgme/libgcrypt RSA verify),
`batch_sign_repo()` (build pipeline signing loop), `show_rpm_signature_info()`
(display Key ID and RSA-4096 key data from signed RPM). Attack scenario notes included.
