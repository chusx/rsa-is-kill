# mastodon-activitypub — RSA-SHA256 federation signatures

**Software:** Mastodon (mastodon/mastodon)  
**Industry:** Decentralized social media / fediverse (ActivityPub)  
**Algorithm:** RSA-2048 / RsaSignature2017  
**PQC migration plan:** None

## What it does

Every Mastodon instance generates a 2048-bit RSA keypair for each user account
(`OpenSSL::PKey::RSA.new(2048)` in `account.rb`). This keypair is used to sign
every ActivityPub activity (posts, follows, likes, boosts) sent to other servers
via HTTP Signatures and LD-Signatures (`RsaSignature2017`).

The fediverse has ~12 million active users across ~20,000 servers. Every piece
of inter-server federation traffic is authenticated with RSA-SHA256. Server
identity (actor keys) is cached across the network.

## Why it's stuck

The signature type is hardcoded as `'RsaSignature2017'`. Changing it requires
a new W3C LD-Signatures algorithm URI, changes to the ActivityPub protocol
spec, and coordinated upgrades across all ~20,000 fediverse servers. There is
no PQC algorithm defined in the W3C LD-Signatures or ActivityPub specifications.

Any CRQC can:
1. Recover any actor's private key from its public key (published in actor JSON)
2. Forge arbitrary posts, follows, or boosts from any user on any server
3. Impersonate entire Mastodon instances to other servers

## why is this hella bad

Any CRQC operator can recover the RSA-2048 private key of any Mastodon actor from their public key (published in every actor's JSON-LD profile at `/.well-known/...`). With it they can:

- **Forge posts from any public figure** — world leaders, journalists, institutions — appearing authentic to all 20,000 servers
- **Impersonate entire instances** — make mastodon.social appear to send announcements or follow/block actions
- **Silently re-sign intercepted activities** — rewrite post content in transit between servers without breaking federation
- The fediverse has no revocation mechanism; a forged key is indistinguishable from the real one until the owner notices and manually notifies every server

## Code

`linked_data_signature.rb` — `sign!` and `verify_actor!` methods showing
`OpenSSL::PKey::RSA` usage and hardcoded `'RsaSignature2017'` type.
