# Source: SAML-Toolkits/ruby-saml lib/xml_security.rb
# ruby-saml is the most widely deployed Ruby SAML library.
# It is used by Okta, Azure AD, Salesforce, GitHub, GitLab, and essentially
# every enterprise SSO integration that speaks SAML 2.0.
# The SAML XML Digital Signatures spec (XMLDSig) is built entirely on RSA.
# All four registered SAML signature algorithms are RSA variants:
#   RSA_SHA1, RSA_SHA256, RSA_SHA384, RSA_SHA512
# The default is RSA_SHA1. There are no PQC algorithms in the XMLDSig spec.
# Every SAML assertion exchanged globally relies on RSA non-repudiation.

class XMLSecurity::Document < BaseDocument
  # All four SAML signature algorithms are RSA — no non-RSA option exists in XMLDSig
  RSA_SHA1        = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  RSA_SHA256      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  RSA_SHA384      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
  RSA_SHA512      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

  # Sign a SAML document. Default: RSA-SHA1. Even RSA-SHA256 is just RSA.
  # signature_method must be one of the RSA_* constants above — XMLDSig
  # has no post-quantum signature algorithm URI registered.
  def sign_document(private_key, certificate,
                    signature_method = RSA_SHA1,   # default is RSA-SHA1
                    digest_method = SHA1,
                    check_malformed_doc = true)

    signature_element = REXML::Element.new("ds:Signature").add_namespace('ds', DSIG)
    signed_info_element = signature_element.add_element("ds:SignedInfo")
    signed_info_element.add_element("ds:CanonicalizationMethod", {"Algorithm" => C14N})
    signed_info_element.add_element("ds:SignatureMethod", {"Algorithm" => signature_method})

    reference_element = signed_info_element.add_element("ds:Reference", {"URI" => "##{uuid}"})
    transforms_element = reference_element.add_element("ds:Transforms")
    transforms_element.add_element("ds:Transform", {"Algorithm" => ENVELOPED_SIG})
    c14element = transforms_element.add_element("ds:Transform", {"Algorithm" => C14N})
    c14element.add_element("ec:InclusiveNamespaces",
                           {"xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST})

    digest_method_element = reference_element.add_element("ds:DigestMethod", {"Algorithm" => digest_method})
    inclusive_namespaces = INC_PREFIX_LIST.split(" ")
    canon_doc = noko.canonicalize(canon_algorithm(C14N), inclusive_namespaces)
    reference_element.add_element("ds:DigestValue").text = compute_digest(canon_doc, algorithm(digest_method_element))

    noko_sig_element = XMLSecurity::BaseDocument.safe_load_xml(signature_element.to_s, check_malformed_doc)
    noko_signed_info_element = noko_sig_element.at_xpath('//ds:Signature/ds:SignedInfo', 'ds' => DSIG)
    canon_string = noko_signed_info_element.canonicalize(canon_algorithm(C14N))

    # private_key.sign() with an RSA key — RSA is the only signing mechanism in XMLDSig
    signature = compute_signature(private_key, algorithm(signature_method).new, canon_string)
    signature_element.add_element("ds:SignatureValue").text = signature

    key_info_element  = signature_element.add_element("ds:KeyInfo")
    x509_element      = key_info_element.add_element("ds:X509Data")
    x509_cert_element = x509_element.add_element("ds:X509Certificate")
    x509_cert_element.text = Base64.encode64(certificate.to_der).gsub(/\n/, "")

    issuer_element = elements["//saml:Issuer"]
    if issuer_element
      root.insert_after(issuer_element, signature_element)
    elsif first_child = root.children[0]
      root.insert_before(first_child, signature_element)
    else
      root.add_element(signature_element)
    end
  end

  protected

  # Delegates to OpenSSL — private_key is always an RSA key for SAML
  def compute_signature(private_key, signature_algorithm, document)
    Base64.encode64(private_key.sign(signature_algorithm, document)).gsub(/\n/, "")
  end
end
