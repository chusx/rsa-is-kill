# frozen_string_literal: true
# Source: mastodon/mastodon app/lib/activitypub/linked_data_signature.rb
# Every Mastodon server signs outgoing ActivityPub activities with RSA-SHA256
# using each actor's 2048-bit RSA keypair (generated in account.rb).
# The signature type is hardcoded as "RsaSignature2017".
# There is no PQC migration path in the ActivityPub/W3C LD-Signatures spec.

class ActivityPub::LinkedDataSignature
  include JsonLdHelper

  CONTEXT = 'https://w3id.org/identity/v1'
  SIGNATURE_CONTEXT = 'https://w3id.org/security/v1'

  def initialize(json)
    @json = json.with_indifferent_access
  end

  def verify_actor!
    return unless @json['signature'].is_a?(Hash)

    type        = @json['signature']['type']
    creator_uri = @json['signature']['creator']
    signature   = @json['signature']['signatureValue']

    return unless type == 'RsaSignature2017'   # hardcoded — no PQC type exists

    keypair = Keypair.from_keyid(creator_uri)
    keypair = ActivityPub::FetchRemoteKeyService.new.call(creator_uri) if keypair&.public_key.blank?
    return if keypair.nil? || !keypair.usable?

    options_hash   = hash(@json['signature'].without('type', 'id', 'signatureValue').merge('@context' => CONTEXT))
    document_hash  = hash(@json.without('signature'))
    to_be_verified = options_hash + document_hash

    keypair.actor if keypair.keypair.public_key.verify(OpenSSL::Digest.new('SHA256'), Base64.decode64(signature), to_be_verified)
  rescue OpenSSL::PKey::RSAError
    false
  end

  def sign!(creator, sign_with: nil)
    options = {
      'type' => 'RsaSignature2017',   # hardcoded — cannot be changed without breaking federation
      'creator' => ActivityPub::TagManager.instance.key_uri_for(creator),
      'created' => Time.now.utc.iso8601,
    }

    options_hash  = hash(options.without('type', 'id', 'signatureValue').merge('@context' => CONTEXT))
    document_hash = hash(@json.without('signature'))
    to_be_signed  = options_hash + document_hash
    keypair       = sign_with.present? ? OpenSSL::PKey::RSA.new(sign_with) : creator.keypair

    signature = Base64.strict_encode64(keypair.sign(OpenSSL::Digest.new('SHA256'), to_be_signed))

    context_with_security = Array(@json['@context'])
    context_with_security << 'https://w3id.org/security/v1'
    context_with_security.uniq!
    context_with_security = context_with_security.first if context_with_security.size == 1

    @json.merge('signature' => options.merge('signatureValue' => signature), '@context' => context_with_security)
  end

  private

  def hash(obj)
    Digest::SHA256.hexdigest(canonicalize(obj))
  end
end

# RSA key generation for each Mastodon actor (account.rb):
#
#   def generate_keys
#     return unless local? && private_key.blank? && public_key.blank?
#     keypair = OpenSSL::PKey::RSA.new(2048)   # 2048-bit RSA hardcoded
#     self.private_key = keypair.to_pem
#     self.public_key  = keypair.public_key.to_pem
#   end
