# frozen_string_literal: true

require 'xmlenc'

module OmniAuth
  module Suomifi
    module Test
      class XmlEncryptor
        attr_reader :certificate, :sign_certificate, :sign_key

        def initialize(opts)
          @certificate = opts[:encryption_certificate]
          @sign_certificate = opts[:sign_certificate]
          @sign_key = opts[:sign_key]
        end

        def encrypt(raw_xml)
          doc = XMLSecurity::Document.new(raw_xml)
          assertion = doc.delete_element('//saml2:Assertion')
          assertion_signed = Utility.sign_xml_element(
            assertion.to_s,
            sign_certificate,
            sign_key
          )

          encrypted = doc.root.add_element(
            'saml2:EncryptedAssertion',
            'xmlns:saml2' => 'urn:oasis:names:tc:SAML:2.0:assertion'
          )
          encrypted.add_element(
            REXML::Document.new(encrypted_node_for(assertion_signed))
          )

          doc.to_s
        end

        def self.encrypted_xml(raw_xml_file, cert, sign_cert, sign_key)
          raw_xml = IO.read(raw_xml_file)
          encrypted_xml_from_string(raw_xml, cert, sign_cert, sign_key)
        end

        def self.encrypted_xml_from_string(raw_xml, cert, sign_cert, sign_key)
          enc = new(
            encryption_certificate: cert,
            sign_certificate: sign_cert,
            sign_key: sign_key
          )

          enc.encrypt(raw_xml)
        end

      private

        def encryption_template
          template_path = Utility.template_filepath(
            'encrypted_data_template.xml'
          )
          template_io = IO.read(template_path)

          Nokogiri::XML::Document.parse(template_io).root
        end

        def encrypted_node_for(raw_xml)
          enc_tpl = encryption_template

          cert_node = enc_tpl.at_xpath(
            '//ds:KeyInfo/xenc:EncryptedKey/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
            Xmlenc::NAMESPACES
          )
          cert_node.content = certificate_string
          encrypted_data = Xmlenc::EncryptedData.new(enc_tpl)
          encryption_key = encrypted_data.encrypt(raw_xml)
          encrypted_key_node = encrypted_data.node.at_xpath(
            '//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey',
            Xmlenc::NAMESPACES
          )
          encrypted_key = Xmlenc::EncryptedKey.new(encrypted_key_node)
          encrypted_key.encrypt(certificate.public_key, encryption_key)

          encrypted_data.node.to_s
        end

        def certificate_string
          certificate.to_pem.gsub(
            /-----((BEGIN CERTIFICATE)|(END CERTIFICATE))-----\n/,
            ''
          ).strip
        end
      end
    end
  end
end
