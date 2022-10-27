# frozen_string_literal: true

require 'spec_helper'

RSpec::Matchers.define :fail_with do |message|
  match do |actual|
    actual.redirect? && actual.location == /\?.*message=#{message}/
  end
end

describe OmniAuth::Strategies::Suomifi, type: :strategy do
  include OmniAuth::Test::StrategyTestCase

  let(:certgen) { OmniAuth::Suomifi::Test::CertificateGenerator.new }
  let(:private_key) { certgen.private_key }
  let(:certificate) { certgen.certificate }

  let(:auth_hash) { last_request.env['omniauth.auth'] }
  let(:saml_options) do
    {
      mode: mode,
      scope_of_data: scope_of_data,
      sp_entity_id: sp_entity_id,
      certificate: certificate.to_pem,
      private_key: private_key.to_pem
    }
  end
  let(:mode) { :test }
  let(:sp_entity_id) { 'https://www.service.fi/auth/suomifi/metadata' }
  let(:scope_of_data) { :medium_extensive }
  let(:strategy) { [OmniAuth::Strategies::Suomifi, saml_options] }
  let(:thread) { double(
    join: nil,
    alive?: false
  )}

  before do
    # Stub the metadata to return the locally stored metadata for easier
    # testing. Otherwise an external HTTP request would be made when the
    # OmniAuth strategy is initialized.
    stub_request(
      :get,
      'https://testi.apro.tunnistus.fi/static/metadata/idp-metadata.xml'
    ).to_return(status: 200, body: File.new(
      support_filepath('idp_metadata.xml')
    ), headers: {})
    allow(Thread).to receive(:new).and_yield.and_return(thread)
  end

  describe '#initialize' do
    subject { post '/auth/suomifi/metadata' }

    it 'should apply the local options and the IdP metadata options' do
      is_expected.to be_successful

      instance = last_request.env['omniauth.strategy']

      # Check the locally set options
      expect(instance.options[:mode]).to eq(:test)
      expect(instance.options[:scope_of_data]).to eq(:medium_extensive)
      expect(instance.options[:sp_entity_id]).to eq(
        'https://www.service.fi/auth/suomifi/metadata'
      )
      expect(instance.options[:certificate]).to eq(certificate.to_pem)
      expect(instance.options[:private_key]).to eq(private_key.to_pem)
      expect(instance.options[:security]).to include(
        'authn_requests_signed' => true,
        'logout_requests_signed' => true,
        'logout_responses_signed' => true,
        'want_assertions_signed' => true,
        'want_assertions_encrypted' => false,
        'want_name_id' => false,
        'metadata_signed' => false,
        'embed_sign' => false,
        'digest_method' => XMLSecurity::Document::SHA256,
        'signature_method' => XMLSecurity::Document::RSA_SHA256,
        'check_idp_cert_expiration' => false,
        'check_sp_cert_expiration' => false
      )

      # Check the automatically set options
      expect(instance.options[:assertion_consumer_service_url]).to eq(
        'https://www.service.fi/auth/suomifi/callback'
      )
      expect(instance.options[:sp_name_qualifier]).to eq(
        'https://www.service.fi/auth/suomifi/metadata'
      )
      expect(instance.options[:idp_name_qualifier]).to eq(
        'https://testi.apro.tunnistus.fi/idp1'
      )

      # Check the most important metadata options
      expect(instance.options[:idp_entity_id]).to eq(
        'https://testi.apro.tunnistus.fi/idp1'
      )
      expect(instance.options[:name_identifier_format]).to eq(
        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
      )
      expect(instance.options[:idp_slo_service_url]).to eq(
        'https://testi.apro.tunnistus.fi/idp/profile/SAML2/Redirect/SLO'
      )
      expect(instance.options[:idp_sso_service_url]).to eq(
        'https://testi.apro.tunnistus.fi/idp/profile/SAML2/Redirect/SSO'
      )

      idp_cert1 = <<~CERT
        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
      CERT
      idp_cert2 = <<~CERT
        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
      CERT

      prefix = "\n"
      suffix = '                    '
      expect(instance.options[:idp_cert_multi][:signing]).to match_array(
        [
          "#{prefix}#{idp_cert1}#{suffix}",
          "#{prefix}#{idp_cert2}#{suffix}"
        ]
      )
    end

    context 'with certificate and private key files' do
      let(:saml_options) do
        {
          mode: :test,
          scope_of_data: scope_of_data,
          sp_entity_id: sp_entity_id,
          certificate_file: certificate_file,
          private_key_file: private_key_file
        }
      end
      let(:certificate_file) { "#{temp_dir}/certificate.crt" }
      let(:private_key_file) { "#{temp_dir}/private.key" }

      around do |example|
        Dir.mktmpdir('rspec-') do |dir|
          @temp_dir = dir
          example.run
        end
      end

      attr_reader :temp_dir

      before do
        File.open(certificate_file, 'w') { |f| f.write(certificate.to_pem) }
        File.open(private_key_file, 'w') { |f| f.write(private_key.to_pem) }
      end

      it 'should read the certificate and private key from the files' do
        is_expected.to be_successful

        instance = last_request.env['omniauth.strategy']
        expect(instance.options[:certificate]).to eq(certificate.to_pem)
        expect(instance.options[:private_key]).to eq(private_key.to_pem)
      end
    end

    context 'with production mode' do
      let(:mode) { :production }

      it 'should hit the production metadata URL' do
        # Note that this needs to return an actual metadata XML because
        # otherwise the strategy initialization will fail. We'll just return
        # the testing metadata since we are only testing that it hits the
        # correct endpoint.
        stub_metadata = stub_request(
          :get,
          'https://tunnistus.suomi.fi/static/metadata/idp-metadata.xml'
        ).to_return(status: 200, body: File.new(
          support_filepath('idp_metadata.xml')
        ), headers: {})

        is_expected.to be_successful
        assert_requested(stub_metadata)
      end
    end
  end

  describe 'POST /auth/suomifi' do
    subject { post '/auth/suomifi' }

    it 'should sign the request' do
      is_expected.to be_redirect

      location = URI.parse(last_response.location)
      query = Rack::Utils.parse_query location.query
      expect(query).to have_key('SAMLRequest')
      expect(query).to have_key('Signature')
      expect(query).to have_key('SigAlg')
      expect(query['SigAlg']).to eq(XMLSecurity::Document::RSA_SHA256)

      # Check that the signature matches
      signature_query = Rack::Utils.build_query(
        'SAMLRequest' => query['SAMLRequest'],
        'SigAlg' => query['SigAlg']
      )
      sign_algorithm = XMLSecurity::BaseDocument.new.algorithm(
        XMLSecurity::Document::RSA_SHA256
      )
      signature = private_key.sign(sign_algorithm.new, signature_query)
      expect(Base64.decode64(query['Signature'])).to eq(signature)
    end

    it 'should create a valid SAML authn request' do
      is_expected.to be_redirect

      location = URI.parse(last_response.location)
      expect(location.scheme).to eq('https')
      expect(location.host).to eq('testi.apro.tunnistus.fi')
      expect(location.path).to eq('/idp/profile/SAML2/Redirect/SSO')

      query = Rack::Utils.parse_query location.query

      xml = OmniAuth::Suomifi::Test::Utility.inflate_xml(query['SAMLRequest'])
      request = REXML::Document.new(xml)
      expect(request.root).not_to be_nil

      acs = request.root.attributes['AssertionConsumerServiceURL']
      dest = request.root.attributes['Destination']
      ii = request.root.attributes['IssueInstant']

      expect(acs).to eq('https://www.service.fi/auth/suomifi/callback')
      expect(dest).to eq('https://testi.apro.tunnistus.fi/idp/profile/SAML2/Redirect/SSO')
      expect(ii).to match(/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z/)

      issuer = request.root.elements['saml:Issuer']
      expect(issuer.text).to eq('https://www.service.fi/auth/suomifi/metadata')
    end

    context 'with extra parameters' do
      subject { post '/auth/suomifi?extra=param' }

      it 'should not add any extra parameters to the redirect assertion consumer service URL' do
        is_expected.to be_redirect

        location = URI.parse(last_response.location)
        query = Rack::Utils.parse_query location.query

        xml = OmniAuth::Suomifi::Test::Utility.inflate_xml(query['SAMLRequest'])
        request = REXML::Document.new(xml)
        acs = request.root.attributes['AssertionConsumerServiceURL']

        expect(acs).to eq('https://www.service.fi/auth/suomifi/callback')
      end
    end

    context 'with locale parameter' do
      shared_examples '' do
        specify { expect(true).to eq true }
      end

      shared_examples 'locale added' do |request_locale, expected_locale|
        subject { post "/auth/suomifi?locale=#{request_locale}" }

        it do
          is_expected.to be_redirect

          location = URI.parse(last_response.location)
          expect(location.query).to match(/&locale=#{expected_locale}$/)
        end
      end

      context 'when set to fi' do
        it_behaves_like 'locale added', 'fi', 'fi'
      end

      context 'when set to fi-FI' do
        it_behaves_like 'locale added', 'fi-FI', 'fi'
      end

      context 'when set to sv' do
        it_behaves_like 'locale added', 'sv', 'sv'
      end

      context 'when set to sv_SE' do
        it_behaves_like 'locale added', 'sv_SE', 'sv'
      end

      context 'when set to en_GB' do
        it_behaves_like 'locale added', 'en_GB', 'en'
      end

      context 'when set to et' do
        it_behaves_like 'locale added', 'et', 'fi'
      end

      context 'when set to de-DE' do
        it_behaves_like 'locale added', 'de-DE', 'fi'
      end

      context 'when set to nb_NO' do
        it_behaves_like 'locale added', 'nb_NO', 'fi'
      end
    end
  end

  describe 'POST /auth/suomifi/callback' do
    subject { last_response }

    let(:xml) { :authn_response_decrypted_unsigned }

    context 'when the response is valid' do
      let(:uid_salt) { 'uidsalt' }
      let(:rails_salt) { nil } # Set this for testing with Rails secret
      let(:saml_options) do
        {
          mode: :test,
          uid_salt: uid_salt,
          scope_of_data: scope_of_data,
          sp_entity_id: sp_entity_id,
          certificate: certificate.to_pem,
          private_key: private_key.to_pem,
          idp_cert_multi: {
            signing: [sign_certificate.to_pem]
          }
        }
      end

      let(:custom_saml_attributes) { [] }

      # Use local certificate and private key for signing because otherwise the
      # locally signed SAMLResponse's signature cannot be properly validated as
      # we cannot sign it using the actual environments private key which is
      # unknown.
      let(:sign_certgen) { OmniAuth::Suomifi::Test::CertificateGenerator.new }
      let(:sign_certificate) { sign_certgen.certificate }
      let(:sign_private_key) { sign_certgen.private_key }

      before :each do
        allow(Time).to receive(:now).and_return(
          Time.utc(2019, 8, 10, 13, 5, 0)
        )

        if rails_salt
          rails = double
          application = double
          secrets = double
          allow(rails).to receive(:application).and_return(application)
          allow(application).to receive(:secrets).and_return(secrets)
          allow(secrets).to receive(:secret_key_base).and_return(rails_salt)
          Object.const_set(:Rails, rails)
        end

        raw_xml_file = support_filepath("#{xml}.xml")
        xml_signed = begin
          if !custom_saml_attributes.empty?
            xml_io = IO.read(raw_xml_file)
            doc = Nokogiri::XML::Document.parse(xml_io)
            statements_node = doc.root.at_xpath(
              '//saml2:Assertion//saml2:AttributeStatement',
              saml2: 'urn:oasis:names:tc:SAML:2.0:assertion'
            )
            custom_saml_attributes.each do |attr|
              attr_def = described_class.default_options[:possible_request_attributes].find do |ra|
                ra[:friendly_name] == attr[:friendly_name]
              end
              next unless attr_def

              attr_node = statements_node.at_xpath(
                "saml2:Attribute[@Name='#{attr_def[:name]}']",
                saml2: 'urn:oasis:names:tc:SAML:2.0:assertion'
              )
              if attr_node.nil?
                attr_node = Nokogiri::XML::Node.new('saml2:Attribute', doc)
                attr_node['FriendlyName'] = attr_def[:friendly_name]
                attr_node['Name'] = attr_def[:name]
                attr_node['NameFormat'] = attr_def[:name_format]

                statements_node.add_child(attr_node)
              else
                attr_node.children.remove
              end

              if attr[:value].nil?
                attr_node.remove
              else
                attr_node.add_child(
                  "<saml2:AttributeValue>#{attr[:value]}</saml2:AttributeValue>"
                )
              end
            end

            OmniAuth::Suomifi::Test::Utility.encrypted_signed_xml_from_string(
              doc.to_s,
              certificate: certificate,
              sign_certificate: sign_certificate,
              sign_private_key: sign_private_key
            )
          else
            OmniAuth::Suomifi::Test::Utility.encrypted_signed_xml(
              raw_xml_file,
              certificate: certificate,
              sign_certificate: sign_certificate,
              sign_private_key: sign_private_key
            )
          end
        end

        saml_response = Base64.encode64(xml_signed)

        post(
          '/auth/suomifi/callback',
          'SAMLResponse' => saml_response
        )
      end

      after :each do
        Object.send(:remove_const, :Rails) if defined?(::Rails)
      end

      it 'should set the info hash correctly' do
        expect(auth_hash['info'].to_hash).to eq(
          'email' => nil,
          'first_name' => 'Nordea',
          'last_name' => 'Demo',
          'location' => 'TURKU',
          'name' => 'Nordea Demo'
        )
      end

      it 'should set the raw info to all attributes' do
        expect(auth_hash['extra']['raw_info'].all.to_hash).to eq(
          'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName' => ['Nordea'],
          'urn:oid:1.2.246.517.2002.2.7' => ['TURKU'],
          'urn:oid:2.16.840.1.113730.3.1.241' => ['Nordea Demo'],
          'urn:oid:1.2.246.517.3002.111.2' => ['true'],
          'urn:oid:1.2.246.517.2002.2.6' => ['20006'],
          'urn:oid:2.5.4.42' => ['Nordea'],
          'urn:oid:1.2.246.517.2002.2.19' => ['Turku'],
          'urn:oid:2.5.4.3' => ['Demo Nordea'],
          'urn:oid:2.5.4.4' => ['Demo'],
          'urn:oid:1.2.246.517.2002.2.18' => ['853'],
          'urn:oid:1.2.246.21' => ['210281-9988'],
          'fingerprint' => nil
        )
      end

      it 'should set the search success state to the extra hash' do
        expect(auth_hash['extra']['search_success']).to be(true)
      end

      it 'should set the saml attributes to the extra hash' do
        expect(auth_hash['extra']['saml_attributes'].to_hash).to eq(
          'electronic_identification_number' => nil,
          'national_identification_number' => '210281-9988',
          'katso_id' => nil,
          'foreign_person_identifier' => nil,
          'email' => nil,
          'common_name' => 'Demo Nordea',
          'display_name' => 'Nordea Demo',
          'first_names' => 'Nordea',
          'given_name' => 'Nordea',
          'last_name' => 'Demo',
          'home_municipality_number' => '853',
          'home_municipality_name_fi' => 'Turku',
          'home_municipality_name_sv' => nil,
          'permanent_domestic_address_street_fi' => nil,
          'permanent_domestic_address_street_sv' => nil,
          'permanent_domestic_address_postal_code' => '20006',
          'permanent_domestic_address_locality_fi' => 'TURKU',
          'permanent_domestic_address_locality_sv' => nil,
          'permanent_foreign_address_street' => nil,
          'permanent_foreign_address_locality_state_fi' => nil,
          'permanent_foreign_address_locality_state_sv' => nil,
          'permanent_foreign_address_locality_state_plain' => nil,
          'permanent_foreign_address_state_code' => nil,
          'temporary_domestic_address_street_fi' => nil,
          'temporary_domestic_address_street_sv' => nil,
          'temporary_domestic_address_postal_code' => nil,
          'temporary_domestic_address_locality_fi' => nil,
          'temporary_domestic_address_locality_sv' => nil,
          'finnish_citizenship' => nil,
          'information_security_denial' => nil,
          'eidas_person_identifier' => nil,
          'eidas_first_names' => 'Nordea',
          'eidas_family_name' => nil,
          'eidas_date_of_birth' => nil
        )
      end

      it 'should set the response_object to the response object from ruby_saml response' do
        expect(auth_hash['extra']['response_object']).to be_kind_of(OneLogin::RubySaml::Response)
      end

      describe '#response_object' do
        subject { instance.response_object }

        let(:instance) { last_request.env['omniauth.strategy'] }

        it 'should return the response object' do
          is_expected.to be_a(OneLogin::RubySaml::Response)
          is_expected.to be_is_valid
        end
      end

      context 'with the SATU ID available in the response' do
        let(:custom_saml_attributes) do
          [
            {
              friendly_name: 'electronicIdentificationNumber',
              value: '012345678N'
            }
          ]
        end

        it 'should set the uid to SATU ID' do
          expect(auth_hash['uid']).to eq('FINUID:012345678N')
        end
      end

      context 'with the HETU ID available in the response' do
        # The HETU is already set in the sample XML
        it 'should set the uid to hashed HETU ID' do
          expect(auth_hash['uid']).to eq(
            'FIHETU:' + Digest::MD5.hexdigest("FI:210281-9988:#{uid_salt}")
          )
        end

        context 'when using Rails salt' do
          let(:uid_salt) { nil }
          let(:rails_salt) { 'railssalt' }

          it 'should set the uid to hashed eIDAS PID' do
            expect(auth_hash['uid']).to eq(
              'FIHETU:' + Digest::MD5.hexdigest("FI:210281-9988:#{rails_salt}")
            )
          end
        end

        context 'when using no salt' do
          let(:uid_salt) { nil }

          it 'should set the uid to hashed eIDAS PID' do
            expect(auth_hash['uid']).to eq(
              'FIHETU:' + Digest::MD5.hexdigest('FI:210281-9988:')
            )
          end
        end
      end

      context 'with the eIDAS PID available in the response' do
        let(:custom_saml_attributes) do
          [
            {
              friendly_name: 'nationalIdentificationNumber',
              value: nil
            },
            {
              friendly_name: 'PersonIdentifier',
              value: '28493196Z' # Spanish DNI
            }
          ]
        end

        it 'should set the uid to hashed eIDAS PID' do
          expect(auth_hash['uid']).to eq(
            'EIDASPID:' + Digest::MD5.hexdigest("EIDAS:28493196Z:#{uid_salt}")
          )
        end

        context 'when using Rails salt' do
          let(:uid_salt) { nil }
          let(:rails_salt) { 'railssalt' }

          it 'should set the uid to hashed eIDAS PID' do
            expect(auth_hash['uid']).to eq(
              'EIDASPID:' + Digest::MD5.hexdigest("EIDAS:28493196Z:#{rails_salt}")
            )
          end
        end

        context 'when using no salt' do
          let(:uid_salt) { nil }

          it 'should set the uid to hashed eIDAS PID' do
            expect(auth_hash['uid']).to eq(
              'EIDASPID:' + Digest::MD5.hexdigest('EIDAS:28493196Z:')
            )
          end
        end
      end

      context 'with no personal identifier available in the response' do
        let(:custom_saml_attributes) do
          [
            {
              friendly_name: 'nationalIdentificationNumber',
              value: nil
            }
          ]
        end

        it 'should set the uid to the SAML name ID' do
          expect(auth_hash['uid']).to eq('AAdzZWNyZXQxfxVUqsT8k/OSMQF/s80N/8TyMb5MERaTUMrYtjpqQV/yStP+CEUegeoHqAVnB9LLOEz2XkE5ZS09VT/4FoAVyonc1z8p5TYIAQI1Hi4wAzINh7OTA6szITMUwP5GfFkW7lGQ0avmRSsr3LODiNGC1zDguiSTX0DtQ9Uq5kQ5nYLz+rJO')
        end
      end
    end

    context 'when response is a logout response' do
      let(:relay_state) { '/relay/uri' }

      before :each do
        post '/auth/suomifi/slo', {
          SAMLResponse: base64_file('logout_response.xml'),
          RelayState: relay_state
        }, 'rack.session' => {
          'saml_transaction_id' => '_b6a69da0-04a2-0134-ea8a-0a2068490f7d'
        }
      end

      it 'should redirect to relaystate' do
        expect(last_response).to be_redirect
        expect(last_response.location).to eq('/relay/uri')
      end

      context 'with a full HTTP URI as relaystate' do
        let(:relay_state) { 'http://www.mainiotech.fi/vuln' }

        it 'should redirect to the root path' do
          expect(last_response.location).to eq('/')
        end
      end

      context 'with a full HTTPS URI as relaystate' do
        let(:relay_state) { 'https://www.mainiotech.fi/vuln' }

        it 'should redirect to the root path' do
          expect(last_response.location).to eq('/')
        end
      end

      context 'with a non-protocol URI as relaystate' do
        let(:relay_state) { '//www.mainiotech.fi/vuln' }

        it 'should redirect to the root path' do
          expect(last_response.location).to eq('/')
        end
      end
    end

    context 'when request is a logout request' do
      subject do
        post(
          '/auth/suomifi/slo',
          params,
          'rack.session' => {'saml_uid' => 'AAdzZWNyZXQxfxVUqsT8k/OSMQF/s80N/8TyMb5MERaTUMrYtjpqQV/yStP+CEUegeoHqAVnB9LLOEz2XkE5ZS09VT/4FoAVyonc1z8p5TYIAQI1Hi4wAzINh7OTA6szITMUwP5GfFkW7lGQ0avmRSsr3LODiNGC1zDguiSTX0DtQ9Uq5kQ5nYLz+rJO'}
        )
      end

      let(:params) { {'SAMLRequest' => base64_file('logout_request.xml')} }

      context 'when logout request is valid' do
        before { subject }

        it 'should redirect to logout response' do
          expect(last_response).to be_redirect
          expect(last_response.location).to match %r{https://testi.apro.tunnistus.fi/idp/profile/SAML2/Redirect/SLO}
        end
      end

      context 'when RelayState is provided' do
        let(:params) { {'SAMLRequest' => base64_file('logout_request.xml'), 'RelayState' => relay_state} }
        let(:relay_state) { nil }

        before { subject }

        context 'with a valid value' do
          let(:relay_state) { '/local/path/to/app' }

          it 'should add the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq(relay_state)
          end
        end

        context 'with a full HTTP URI' do
          let(:relay_state) { 'http://www.mainiotech.fi/vuln' }

          it 'should add root URI as the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq('/')
          end
        end

        context 'with a full HTTPS URI' do
          let(:relay_state) { 'https://www.mainiotech.fi/vuln' }

          it 'should add root URI as the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq('/')
          end
        end

        context 'with a non-protocol URI' do
          let(:relay_state) { '//www.mainiotech.fi/vuln' }

          it 'should add root URI as the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq('/')
          end
        end
      end
    end

    context 'when sp initiated SLO' do
      let(:params) { nil }

      before { post('/auth/suomifi/spslo', params) }

      it 'should redirect to logout request' do
        expect(last_response).to be_redirect
        expect(last_response.location).to match %r{https://testi.apro.tunnistus.fi/idp/profile/SAML2/Redirect/SLO}
      end

      context 'when RelayState is provided' do
        let(:params) { {'RelayState' => relay_state} }
        let(:relay_state) { nil }

        context 'with a valid value' do
          let(:relay_state) { '/local/path/to/app' }

          it 'should add the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq(relay_state)
          end
        end

        context 'with a full HTTP URI' do
          let(:relay_state) { 'http://www.mainiotech.fi/vuln' }

          it 'should add root URI as the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq('/')
          end
        end

        context 'with a full HTTPS URI' do
          let(:relay_state) { 'https://www.mainiotech.fi/vuln' }

          it 'should add root URI as the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq('/')
          end
        end

        context 'with a non-protocol URI' do
          let(:relay_state) { '//www.mainiotech.fi/vuln' }

          it 'should add root URI as the RelayState parameter to the response' do
            expect(last_response).to be_redirect

            location = URI.parse(last_response.location)
            query = Rack::Utils.parse_query location.query
            expect(query['RelayState']).to eq('/')
          end
        end
      end
    end
  end

  describe 'POST /auth/suomifi/metadata' do
    subject { post '/auth/suomifi/metadata' }

    let(:response_xml) { Nokogiri::XML(last_response.body) }
    let(:request_attribute_nodes) do
      response_xml.xpath('//md:EntityDescriptor//md:SPSSODescriptor//md:AttributeConsumingService//md:RequestedAttribute')
    end
    let(:request_attributes) do
      request_attribute_nodes.map do |node|
        {
          friendly_name: node['FriendlyName'],
          name: node['Name']
        }
      end
    end

    before do
      is_expected.to be_successful
    end

    context 'with scope of data set to :limited' do
      let(:scope_of_data) { :limited }

      it 'should add the correct request attributes' do
        expect(request_attributes).to match_array(
          [
            {friendly_name: 'electronicIdentificationNumber', name: 'urn:oid:1.2.246.22'},
            {friendly_name: 'nationalIdentificationNumber', name: 'urn:oid:1.2.246.21'},
            {friendly_name: 'kid', name: 'urn:oid:1.2.246.517.3003.113.4'},
            {friendly_name: 'foreignpersonIdentifier', name: 'urn:oid:1.2.246.517.3002.111.17'},
            {friendly_name: 'cn', name: 'urn:oid:2.5.4.3'},
            {friendly_name: 'displayName', name: 'urn:oid:2.16.840.1.113730.3.1.241'},
            {friendly_name: 'FirstName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'},
            {friendly_name: 'givenName', name: 'urn:oid:2.5.4.42'},
            {friendly_name: 'sn', name: 'urn:oid:2.5.4.4'},
            {friendly_name: 'PersonIdentifier', name: 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'},
            {friendly_name: 'FamilyName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'},
            {friendly_name: 'DateOfBirth', name: 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth'}
          ]
        )
      end
    end

    context 'with scope of data set to :medium_extensive' do
      let(:scope_of_data) { :medium_extensive }

      it 'should add the correct request attributes' do
        expect(request_attributes).to match_array(
          [
            {friendly_name: 'electronicIdentificationNumber', name: 'urn:oid:1.2.246.22'},
            {friendly_name: 'nationalIdentificationNumber', name: 'urn:oid:1.2.246.21'},
            {friendly_name: 'kid', name: 'urn:oid:1.2.246.517.3003.113.4'},
            {friendly_name: 'foreignpersonIdentifier', name: 'urn:oid:1.2.246.517.3002.111.17'},
            {friendly_name: 'mail', name: 'urn:oid:0.9.2342.19200300.100.1.3'},
            {friendly_name: 'cn', name: 'urn:oid:2.5.4.3'},
            {friendly_name: 'displayName', name: 'urn:oid:2.16.840.1.113730.3.1.241'},
            {friendly_name: 'FirstName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'},
            {friendly_name: 'givenName', name: 'urn:oid:2.5.4.42'},
            {friendly_name: 'sn', name: 'urn:oid:2.5.4.4'},
            {friendly_name: 'KotikuntaKuntanumero', name: 'urn:oid:1.2.246.517.2002.2.18'},
            {friendly_name: 'KotikuntaKuntaS', name: 'urn:oid:1.2.246.517.2002.2.19'},
            {friendly_name: 'KotikuntaKuntaR', name: 'urn:oid:1.2.246.517.2002.2.20'},
            {friendly_name: 'VakinainenKotimainenLahiosoiteS', name: 'urn:oid:1.2.246.517.2002.2.4'},
            {friendly_name: 'VakinainenKotimainenLahiosoiteR', name: 'urn:oid:1.2.246.517.2002.2.5'},
            {friendly_name: 'VakinainenKotimainenLahiosoitePostinumero', name: 'urn:oid:1.2.246.517.2002.2.6'},
            {friendly_name: 'VakinainenKotimainenLahiosoitePostitoimipaikkaS', name: 'urn:oid:1.2.246.517.2002.2.7'},
            {friendly_name: 'VakinainenKotimainenLahiosoitePostitoimipaikkaR', name: 'urn:oid:1.2.246.517.2002.2.8'},
            {friendly_name: 'VakinainenUlkomainenLahiosoite', name: 'urn:oid:1.2.246.517.2002.2.11'},
            {friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioS', name: 'urn:oid:1.2.246.517.2002.2.12'},
            {friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioR', name: 'urn:oid:1.2.246.517.2002.2.13'},
            {friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioSelvakielinen', name: 'urn:oid:1.2.246.517.2002.2.14'},
            {friendly_name: 'VakinainenUlkomainenLahiosoiteValtiokoodi', name: 'urn:oid:1.2.246.517.2002.2.15'},
            {friendly_name: 'TilapainenKotimainenLahiosoiteS', name: 'urn:oid:1.2.246.517.2002.2.31'},
            {friendly_name: 'TilapainenKotimainenLahiosoiteR', name: 'urn:oid:1.2.246.517.2002.2.32'},
            {friendly_name: 'TilapainenKotimainenLahiosoitePostinumero', name: 'urn:oid:1.2.246.517.2002.2.33'},
            {friendly_name: 'TilapainenKotimainenLahiosoitePostitoimipaikkaS', name: 'urn:oid:1.2.246.517.2002.2.34'},
            {friendly_name: 'TilapainenKotimainenLahiosoitePostitoimipaikkaR', name: 'urn:oid:1.2.246.517.2002.2.35'},
            {friendly_name: 'TurvakieltoTieto', name: 'urn:oid:1.2.246.517.2002.2.27'},
            {friendly_name: 'PersonIdentifier', name: 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'},
            {friendly_name: 'FamilyName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'},
            {friendly_name: 'DateOfBirth', name: 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth'}
          ]
        )
      end
    end

    context 'with scope of data set to :extensive' do
      let(:scope_of_data) { :extensive }

      it 'should add the correct request attributes' do
        expect(request_attributes).to match_array(
          [
            {friendly_name: 'electronicIdentificationNumber', name: 'urn:oid:1.2.246.22'},
            {friendly_name: 'nationalIdentificationNumber', name: 'urn:oid:1.2.246.21'},
            {friendly_name: 'kid', name: 'urn:oid:1.2.246.517.3003.113.4'},
            {friendly_name: 'foreignpersonIdentifier', name: 'urn:oid:1.2.246.517.3002.111.17'},
            {friendly_name: 'mail', name: 'urn:oid:0.9.2342.19200300.100.1.3'},
            {friendly_name: 'cn', name: 'urn:oid:2.5.4.3'},
            {friendly_name: 'displayName', name: 'urn:oid:2.16.840.1.113730.3.1.241'},
            {friendly_name: 'FirstName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'},
            {friendly_name: 'givenName', name: 'urn:oid:2.5.4.42'},
            {friendly_name: 'sn', name: 'urn:oid:2.5.4.4'},
            {friendly_name: 'KotikuntaKuntanumero', name: 'urn:oid:1.2.246.517.2002.2.18'},
            {friendly_name: 'KotikuntaKuntaS', name: 'urn:oid:1.2.246.517.2002.2.19'},
            {friendly_name: 'KotikuntaKuntaR', name: 'urn:oid:1.2.246.517.2002.2.20'},
            {friendly_name: 'VakinainenKotimainenLahiosoiteS', name: 'urn:oid:1.2.246.517.2002.2.4'},
            {friendly_name: 'VakinainenKotimainenLahiosoiteR', name: 'urn:oid:1.2.246.517.2002.2.5'},
            {friendly_name: 'VakinainenKotimainenLahiosoitePostinumero', name: 'urn:oid:1.2.246.517.2002.2.6'},
            {friendly_name: 'VakinainenKotimainenLahiosoitePostitoimipaikkaS', name: 'urn:oid:1.2.246.517.2002.2.7'},
            {friendly_name: 'VakinainenKotimainenLahiosoitePostitoimipaikkaR', name: 'urn:oid:1.2.246.517.2002.2.8'},
            {friendly_name: 'VakinainenUlkomainenLahiosoite', name: 'urn:oid:1.2.246.517.2002.2.11'},
            {friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioS', name: 'urn:oid:1.2.246.517.2002.2.12'},
            {friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioR', name: 'urn:oid:1.2.246.517.2002.2.13'},
            {friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioSelvakielinen', name: 'urn:oid:1.2.246.517.2002.2.14'},
            {friendly_name: 'VakinainenUlkomainenLahiosoiteValtiokoodi', name: 'urn:oid:1.2.246.517.2002.2.15'},
            {friendly_name: 'TilapainenKotimainenLahiosoiteS', name: 'urn:oid:1.2.246.517.2002.2.31'},
            {friendly_name: 'TilapainenKotimainenLahiosoiteR', name: 'urn:oid:1.2.246.517.2002.2.32'},
            {friendly_name: 'TilapainenKotimainenLahiosoitePostinumero', name: 'urn:oid:1.2.246.517.2002.2.33'},
            {friendly_name: 'TilapainenKotimainenLahiosoitePostitoimipaikkaS', name: 'urn:oid:1.2.246.517.2002.2.34'},
            {friendly_name: 'TilapainenKotimainenLahiosoitePostitoimipaikkaR', name: 'urn:oid:1.2.246.517.2002.2.35'},
            {friendly_name: 'TurvakieltoTieto', name: 'urn:oid:1.2.246.517.2002.2.27'},
            {friendly_name: 'PersonIdentifier', name: 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'},
            {friendly_name: 'FamilyName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'},
            {friendly_name: 'DateOfBirth', name: 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth'},
            {friendly_name: 'SuomenKansalaisuusTietokoodi', name: 'urn:oid:1.2.246.517.2002.2.26'}
          ]
        )
      end
    end
  end
end
