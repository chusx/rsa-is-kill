# mastodon-activitypub — RSA-SHA256 federation signatures

**Software:** Mastodon (mastodon/mastodon) 
**Industry:** Decentralized social media / fediverse (ActivityPub) 
**Algorithm:** RSA-2048 / RsaSignature2017 

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
no non-RSA algorithm defined in the W3C LD-Signatures or ActivityPub specifications.

A factoring break lets an attacker:
1. Recover any actor's private key from its public key (published in actor JSON)
2. Forge arbitrary posts, follows, or boosts from any user on any server
3. Impersonate entire Mastodon instances to other servers

## impact

every Mastodon actor has an RSA-2048 public key sitting in their JSON-LD profile at /.well-known/ and it's publicly accessible. input for the attack delivered by the protocol spec.

- forge posts from any public figure (politicians, journalists, institutions) and they look authentic to all 20,000 servers in the federation. ActivityPub signature verification is what makes posts trusted, and it's all RSA
- impersonate entire instances: make mastodon.social appear to send announcements, follow/unfollow/block actions, or federation policy changes
- inject fake profile updates for any account. change bios, add links, change display names across the whole fediverse
- there is no centralized authority to issue retractions. once a forged post federates it's in 20,000 databases simultaneously. there's no recall mechanism
## Code

`linked_data_signature.rb` — `sign!` and `verify_actor!` methods showing
`OpenSSL::PKey::RSA` usage and hardcoded `'RsaSignature2017'` type.
