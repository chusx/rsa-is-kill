# http_signature_middleware.rb
#
# ActivityPub HTTP Signatures — the RSA-SHA256 signature layer that
# federated servers (Mastodon, Pleroma, Akkoma, Misskey, GotoSocial,
# Firefish, Iceshrimp) use on every federation POST / inbox delivery.
# Sits alongside the Linked Data Signature logic in
# `linked_data_signature.rb` (which signs the activity content itself);
# this file signs the *HTTP transport* of the activity.
#
# Every Create/Note, Announce (boost), Follow, Like, Block, Undo, Move,
# Delete/Tombstone activity — the full daily volume of the Fediverse
# (~15M MAU as of 2026, hundreds of millions of deliveries/day) — is
# authenticated with one of these signatures before a receiving inbox
# will deliver it into its timeline ingestion pipeline.

require 'openssl'
require 'base64'
require 'net/http'
require 'uri'

module ActivityPub
  # ---- Outbound: sign delivery request ----
  class SignedDelivery
    # `actor` must expose #private_key_pem (PKCS#8 RSA-2048) and
    # #public_key_id (URL to the actor's JSON-LD public key fragment,
    # e.g. https://example.social/users/alice#main-key).
    def initialize(actor)
      @actor = actor
      @key   = OpenSSL::PKey::RSA.new(actor.private_key_pem)
    end

    def deliver(activity_json, inbox_url)
      uri = URI(inbox_url)
      body_digest = "SHA-256=" + Base64.strict_encode64(
        OpenSSL::Digest::SHA256.digest(activity_json))
      date = Time.now.utc.httpdate

      # Canonical string: (request-target) host date digest
      signed_string = <<~STR.chomp
        (request-target): post #{uri.path}
        host: #{uri.host}
        date: #{date}
        digest: #{body_digest}
      STR

      signature = Base64.strict_encode64(
        @key.sign(OpenSSL::Digest::SHA256.new, signed_string))

      sig_header = %(
        keyId="#{@actor.public_key_id}",
        algorithm="rsa-sha256",
        headers="(request-target) host date digest",
        signature="#{signature}"
      ).gsub("\n", "").squeeze(" ")

      req = Net::HTTP::Post.new(uri)
      req["Host"]          = uri.host
      req["Date"]          = date
      req["Digest"]        = body_digest
      req["Content-Type"]  = "application/activity+json"
      req["Signature"]     = sig_header
      req.body = activity_json

      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |h|
        h.request(req)
      end
    end
  end

  # ---- Inbound: Rack middleware that verifies the signature on
  #      every POST to /inbox and /users/*/inbox ----
  class VerifyInboxSignature
    def initialize(app); @app = app; end

    def call(env)
      req = Rack::Request.new(env)
      if req.post? && req.path =~ %r{(?:^|/)inbox\z}
        return [401, {}, []] unless verify_signature(env)
      end
      @app.call(env)
    end

    private

    def verify_signature(env)
      sig_header = env["HTTP_SIGNATURE"] or return false
      fields = sig_header.scan(/(\w+)="([^"]+)"/).to_h

      # 1. Resolve keyId → actor JSON → publicKeyPem
      key_uri = URI(fields["keyId"])
      actor_doc = fetch_json(key_uri.to_s.split("#").first)
      pem = dig(actor_doc, "publicKey", "publicKeyPem") ||
            dig_array(actor_doc, "publicKey", "publicKeyPem")
      pubkey = OpenSSL::PKey::RSA.new(pem)

      # 2. Recompute signed string (same canonicalization as sender)
      headers = fields["headers"].split(" ")
      signed_string = headers.map do |h|
        if h == "(request-target)"
          "(request-target): #{env['REQUEST_METHOD'].downcase} #{env['PATH_INFO']}"
        else
          "#{h}: #{env["HTTP_#{h.upcase.tr('-', '_')}"]}"
        end
      end.join("\n")

      # 3. Verify. Most Fediverse actors are RSA-2048; key rotation
      #    is rare, so the same key often signs every delivery a
      #    server ever makes.
      pubkey.verify(OpenSSL::Digest::SHA256.new,
                     Base64.decode64(fields["signature"]),
                     signed_string)
    rescue StandardError
      false
    end

    def fetch_json(url); end
    def dig(h, *k); end
    def dig_array(h, *k); end
  end
end

# ---- Breakage ----
#
# Every ActivityPub activity on the Fediverse is authenticated by a
# remote-host HTTP Signature over RSA-SHA256. A factoring attack on a
# given actor's RSA-2048 key lets an attacker:
#   - Impersonate that actor on every receiving instance, posting or
#     boosting as them, muting no one, following anyone.
#   - Pre-emptively Delete/Tombstone their legitimate posts across
#     the network — unrecoverable once a Delete federates.
#   - Block/Report other users under the actor's identity, triggering
#     moderator workflows.
# Mass-factoring (say, all actors on a specific instance whose public
# keys sit in a searchable JSON-LD directory) turns into instance-
# scale takeover. The Fediverse has no mechanism for mass key
# rotation — each actor's key is burned into its
# Actor object and referenced in every outbound delivery.
