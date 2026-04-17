# sp_idp_integration.rb
#
# Typical Rails SP <-> IdP SAML 2.0 bring-up using ruby-saml. The
# RSA primitives invoked here live in `xml_security_rsa.rb` — this
# file shows how they're called across the Web-SSO login + SLO +
# metadata-refresh paths actually running in production.
#
# ruby-saml is embedded in: GitLab (self-managed + gitlab.com SSO),
# Discourse, Zammad, Mastodon admin SSO, Shopify internal tools,
# Rails-based CRM/HRIS at thousands of mid-market SaaS companies.
# Shibboleth SP + SimpleSAMLphp + Microsoft Entra ID (Azure AD) +
# Okta + PingFederate + Keycloak all sit on the IdP side of these
# flows — with XMLDSig-RSA signatures at every turn.

require "onelogin/ruby-saml"
require "net/http"
require "nokogiri"

# ---- Application-wide SAML config -----------------------------------

def saml_settings
  s = OneLogin::RubySaml::Settings.new

  # SP identifiers / endpoints
  s.issuer                       = "https://app.example.com/saml/metadata"
  s.assertion_consumer_service_url = "https://app.example.com/saml/acs"
  s.single_logout_service_url    = "https://app.example.com/saml/slo"

  # IdP metadata (fetched from Okta/Entra/PingFederate, refreshed daily)
  idp_meta = OneLogin::RubySaml::IdpMetadataParser.new.parse_remote(
    "https://corp.okta.com/app/exk123/sso/saml/metadata"
  )
  s = OneLogin::RubySaml::IdpMetadataParser.new.parse_to_idp_settings(idp_meta, s)

  # RSA key + cert that sign *our* SP-side requests (AuthnRequest,
  # LogoutRequest) and decrypt IdP-encrypted assertions. Private key
  # is loaded via env/secrets-manager, never on disk in prod.
  s.certificate     = ENV["SAML_SP_CERT_PEM"]
  s.private_key     = ENV["SAML_SP_KEY_PEM"]

  # Mandatory: signed AuthnRequests, signed IdP responses, signed
  # LogoutResponses. Every signature is RSA-SHA256 over the
  # canonicalized XML per XMLDSig.
  s.security[:authn_requests_signed]  = true
  s.security[:logout_requests_signed] = true
  s.security[:logout_responses_signed] = true
  s.security[:want_assertions_signed] = true
  s.security[:want_assertions_encrypted] = true
  s.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
  s.security[:digest_method]    = XMLSecurity::Document::SHA256

  s
end

# ---- ACS: IdP POSTs a signed SAMLResponse to us ---------------------
# Every production-grade ACS endpoint validates: (a) the
# XMLDSig over Assertion via `xml_security_rsa.rb`'s
# validate_signature; (b) the IdP cert thumbprint against pinned
# metadata; (c) InResponseTo correlation; (d) NotOnOrAfter window;
# (e) Audience = our SP entity-id.
post "/saml/acs" do
  resp = OneLogin::RubySaml::Response.new(params[:SAMLResponse],
                                          settings: saml_settings)
  halt 401, resp.errors.join(", ") unless resp.is_valid?

  # Tie to session; ruby-saml exposes name_id + attributes.
  session[:user_email] = resp.name_id
  session[:groups]     = Array(resp.attributes.multi("groups"))
  redirect "/"
end

# ---- SP-initiated SSO -----------------------------------------------
get "/auth/saml" do
  req = OneLogin::RubySaml::Authrequest.new
  redirect req.create(saml_settings,
                      RelayState: params[:return_to] || "/")
end

# ---- SLO (back-channel logout) --------------------------------------
post "/saml/slo" do
  slo = OneLogin::RubySaml::SloLogoutrequest.new(params[:SAMLRequest])
  # Verify the IdP-side XMLDSig before wiping our session.
  halt 401 unless slo.is_valid?
  session.clear
  resp = OneLogin::RubySaml::SloLogoutresponse.new.create(
    saml_settings, slo.id)
  redirect resp
end


# ---- Breakage --------------------------------------------------------
#
# A factoring attack against the IdP's SAML signing RSA key (typically
# RSA-2048, occasionally RSA-3072) lets an attacker:
#   - Mint a SAMLResponse asserting ANY user's NameID + group
#     attributes.  The SP cannot distinguish forged assertions from
#     legitimate Okta/Entra/PingFederate output — `is_valid?`
#     returns true because the signature verifies.
#   - Walk straight into GitLab as root, Shopify admin as
#     platform-admin, internal HRIS as payroll-officer — no
#     password, no MFA, no device-trust check reaches this code path
#     once the signature passes.
#   - Persist as long as the SP keeps metadata cached with the
#     forgeable key; key rotation is an out-of-band IdP-side
#     operation that takes days to propagate across the long tail of
#     SAML consumers.
