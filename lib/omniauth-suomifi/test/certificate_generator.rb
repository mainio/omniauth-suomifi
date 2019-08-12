# frozen_string_literal: true

module OmniAuth
  module Suomifi
    module Test
      class CertificateGenerator
        def private_key
          @private_key ||= OpenSSL::PKey::RSA.new(2048)
        end

        def certificate
          @certificate ||= begin
            public_key = private_key.public_key

            subject = '/C=FI/O=Test/OU=Test/CN=Test'

            cert = OpenSSL::X509::Certificate.new
            cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
            cert.not_before = Time.now
            cert.not_after = Time.now + 365 * 24 * 60 * 60
            cert.public_key = public_key
            cert.serial = 0x0
            cert.version = 2

            inject_certificate_extensions(cert)

            cert.sign(private_key, OpenSSL::Digest::SHA1.new)

            cert
          end
        end

      private

        def inject_certificate_extensions(cert)
          ef = OpenSSL::X509::ExtensionFactory.new
          ef.subject_certificate = cert
          ef.issuer_certificate = cert
          cert.extensions = [
            ef.create_extension('basicConstraints', 'CA:TRUE', true),
            ef.create_extension('subjectKeyIdentifier', 'hash')
          ]
          cert.add_extension ef.create_extension(
            'authorityKeyIdentifier',
            'keyid:always,issuer:always'
          )
        end
      end
    end
  end
end
