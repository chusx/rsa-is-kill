# openssh-host-keys — RSA host key authentication in SSH

**Software:** OpenSSH (openssh/openssh-portable on GitHub) 
**Industry:** Infrastructure, servers, cloud, network equipment 
**Algorithm:** RSA-2048 / RSA-3072 host keys (ssh-rsa, rsa-sha2-256, rsa-sha2-512) 

## What it does

Every SSH server has a host key. The host key is an RSA (or ECDSA/Ed25519) keypair
used during key exchange to prove the server's identity to connecting clients.
The public host key is stored in `~/.ssh/known_hosts` on every client that has ever
connected, and is also indexed by internet-wide scanners (Shodan, Censys, FOFA, etc.).

RSA host keys are still the most common host key type in deployed infrastructure,
especially:
- Legacy Linux servers (pre-systemd, older distros defaulted to RSA-only)
- Network equipment (routers, switches running SSH for management)
- Embedded devices and IoT gateways (BusyBox-based SSH servers)
- Older cloud VM images with RSA host keys from first boot

The server signs the session exchange hash during key exchange with its RSA private
key. The client verifies this signature against the cached host key. If the attacker
can forge this signature, they can impersonate any SSH server whose public key they've
seen.

## Why it's stuck

- No non-RSA algorithm has been standardized in any SSH RFC. The IETF SSHM working group
 has drafts for hybrid ML-KEM key exchange but nothing for host key authentication
- OpenSSH has an experimental OQS (liboqs) fork but it's not in the upstream codebase
- Rotating host keys requires updating `known_hosts` on every client — for large
 enterprises with thousands of clients, this is operationally painful and rarely done
- Network equipment (Cisco IOS, Junos, etc.) has no mechanism to update SSH host key
 algorithms without firmware updates, and firmware cycles are slow

## impact

SSH host keys are the mechanism by which your terminal client knows it's connecting
to the real server and not an impersonator. every RSA host key in every server's
`/etc/ssh/ssh_host_rsa_key.pub` has been scanned and archived by Shodan. the factoring break
input is already collected.

- factor any server's RSA host key (publicly available from Shodan/Censys scan history),
 impersonate that server to any client that has it cached in known_hosts. the client
 sees a valid signature and connects. transparent MitM of every SSH session to that
 server
- every router and switch with RSA SSH host keys (which is most of them) is
 impersonatable. SSH into network equipment, reconfigure routing, change ACLs,
 install backdoors. no client prompts, no verification failures
- CI/CD pipelines use SSH host key verification to ensure they're pushing code to
 the real server. forge the git server's host key and you can MitM deployments,
 inject malicious code into the build pipeline
- known_hosts files on developer laptops are essentially an archive of every server's
 public key that developer has connected to, going back years. all of those are
 input for the attack for impersonating every server in that developer's history

## Code

`openssh_rsa_hostkey.c` — `ssh_rsa_sign()` (server signs session exchange hash with
RSA host private key) and `ssh_rsa_verify()` (client verifies the signature), with
notes on the hash algorithm dispatch (ssh-rsa, rsa-sha2-256, rsa-sha2-512).
