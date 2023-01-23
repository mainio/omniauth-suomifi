# frozen_string_literal: true

require 'omniauth-saml'

module OmniAuth
  module Strategies
    class Suomifi < SAML
      # Mode:
      # :production - Suomi.fi production environment
      # :test - Suomi.fi test environment
      option :mode, :production

      # The certificate file to define the certificate.
      option :certificate_file, nil

      # The private key file to define the private key.
      option :private_key_file, nil

      # Defines the locale parameters to check from the request phase request
      # parameters. A valid language will be added to the IdP sign in redirect
      # URL as the last parameter (with the name `locale` as expected by
      # Suomi.fi).
      #
      # Suomi.fi accepts `fi`, `sv` or `en` in this parameter. The language can
      # be parsed from the following kind of strings:
      # - fi
      # - sv-SE
      # - en_US
      #
      # In case a valid language cannot be parsed from the parameter, the locale
      # parameter will default to `:idp_sso_service_url_default_locale`.
      #
      # Note that the locale parameter is always added as the last parameter in
      # in the redirect URL as expected by Suomi.fi.
      option :idp_sso_service_url_locale_params, %w[locale language lang]

      # This is the default locale to be passed to IdP sign in redirect URL as
      # defined above. In case a valid locale is not found from the request
      # parameters, this will be used instead.
      option :idp_sso_service_url_default_locale, 'fi'

      # The request attributes for Suomi.fi
      option :possible_request_attributes, [
        ##############################
        ### Finnish authentication ###
        ##############################
        # Electronic identification number
        # Sähköinen asiointitunnus
        {
          name: 'urn:oid:1.2.246.22',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'electronicIdentificationNumber'
        },
        # National identification number
        # Henkilötunnus
        {
          name: 'urn:oid:1.2.246.21',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'nationalIdentificationNumber'
        },
        # Katso-ID
        {
          name: 'urn:oid:1.2.246.517.3003.113.4',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'kid'
        },
        # Foreign person identifier
        # Ulkomaisen henkilön tunniste
        {
          name: 'urn:oid:1.2.246.517.3002.111.17',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'foreignpersonIdentifier'
        },
        # Email address
        # Sähköpostiosoite
        {
          name: 'urn:oid:0.9.2342.19200300.100.1.3',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mail'
        },
        # Name, common name (full name = family name + all first names)
        # Nimi, common name (koko nimi = sukunimi + kaikki etunimet)
        {
          name: 'urn:oid:2.5.4.3',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'cn'
        },
        # Full name (calling name + last name)
        # Koko nimi (kutsumanimi + sukunimi)
        {
          name: 'urn:oid:2.16.840.1.113730.3.1.241',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'displayName'
        },
        # First names
        # Etunimet
        # NOTE: Also available in the eIDAS attributes
        {
          name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'FirstName'
        },
        # Given name
        # Kutsumanimi
        {
          name: 'urn:oid:2.5.4.42',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'givenName'
        },
        # Last name
        # Sukunimi
        {
          name: 'urn:oid:2.5.4.4',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'sn'
        },
        # Home municipality number
        # Kotikunnan numero
        # Defined at:
        # http://tilastokeskus.fi/meta/luokitukset/kunta/001-2017/index.html
        # http://tilastokeskus.fi/meta/luokitukset/kunta/001-2017/index_en.html
        {
          name: 'urn:oid:1.2.246.517.2002.2.18',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'KotikuntaKuntanumero'
        },
        # Home municipality in Finnish
        # Kotikunta suomeksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.19',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'KotikuntaKuntaS'
        },
        # Home municipality in Swedish
        # Kotikunta ruotsiksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.20',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'KotikuntaKuntaR'
        },
        # Permanent domestic postal address, street address in Finnish
        # Vakinainen kotimainen lähiosoite, katuosoite suomeksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.4',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenKotimainenLahiosoiteS'
        },
        # Permanent domestic postal address, street address in Swedish
        # Vakinainen kotimainen lähiosoite, katuosoite ruotsiksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.5',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenKotimainenLahiosoiteR'
        },
        # Permanent domestic postal address, postal code
        # Vakinainen kotimainen lähiosoite, postinumero
        {
          name: 'urn:oid:1.2.246.517.2002.2.6',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenKotimainenLahiosoitePostinumero'
        },
        # Permanent domestic postal address, municipality name (locality) in Finnish
        # Vakinainen kotimainen lähiosoite, postitoimipaikka suomeksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.7',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenKotimainenLahiosoitePostitoimipaikkaS'
        },
        # Permanent domestic postal address, municipality name (locality) in Swedish
        # Vakinainen kotimainen lähiosoite, postitoimipaikka ruotsiksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.8',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenKotimainenLahiosoitePostitoimipaikkaR'
        },
        # Permanent foreign postal address, street address
        # Vakinainen ulkomainen lähiosoite, katuosoite
        {
          name: 'urn:oid:1.2.246.517.2002.2.11',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenUlkomainenLahiosoite'
        },
        # Permanent foreign postal address, municipality (locality) and state in Finnish
        # Vakinainen ulkomainen lähiosoite, paikkakunta ja valtio suomeksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.12',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioS'
        },
        # Permanent foreign postal address, municipality (locality) and state in Swedish
        # Vakinainen ulkomainen lähiosoite, paikkakunta ja valtio ruotsiksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.13',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioR'
        },
        # Permanent foreign postal address, municipality (locality) and state in plain text
        # Vakinainen ulkomainen lähiosoite, paikkakunta ja valtio selväkielinen
        # In case the foreign state name is not in the ISO3166 standard, it will
        # be defined here in plain text.
        {
          name: 'urn:oid:1.2.246.517.2002.2.14',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioSelvakielinen'
        },
        # Permanent foreign address state code
        # Vakinaisen ulkomaisen osoitteen valtiokoodi
        # In case the state is defined in the ISO3166 standard.
        {
          name: 'urn:oid:1.2.246.517.2002.2.15',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'VakinainenUlkomainenLahiosoiteValtiokoodi'
        },
        # Temporary domestic postal address, street address in Finnish
        # Tilapäinen kotimainen lähiosoite, katuosoite suomeksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.31',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'TilapainenKotimainenLahiosoiteS'
        },
        # Temporary domestic postal address, street address in Swedish
        # Tilapäinen kotimainen lähiosoite, katuosoite ruotsiksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.32',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'TilapainenKotimainenLahiosoiteR'
        },
        # Temporary domestic postal address, postal code
        # Tilapäinen kotimainen lähiosoite, postinumero
        {
          name: 'urn:oid:1.2.246.517.2002.2.33',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'TilapainenKotimainenLahiosoitePostinumero'
        },
        # Temporary domestic postal address, municipality name (locality) in Finnish
        # Tilapäinen kotimainen lähiosoite, postitoimipaikka suomeksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.34',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'TilapainenKotimainenLahiosoitePostitoimipaikkaS'
        },
        # Temporary domestic postal address, municipality name (locality) in Swedish
        # Tilapäinen kotimainen lähiosoite, postitoimipaikka ruotsiksi
        {
          name: 'urn:oid:1.2.246.517.2002.2.35',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'TilapainenKotimainenLahiosoitePostitoimipaikkaR'
        },
        # Finnish citizenship
        # Suomen kansalaisuus
        # In case the person is a Finnish citizen, the value of this will be
        # '1'. Note that in order to get this information, the scope of the
        # fetched data needs to be the 'extensive personal data'.
        {
          name: 'urn:oid:1.2.246.517.2002.2.26',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'SuomenKansalaisuusTietokoodi'
        },
        # Information security denial
        # Turvakielto
        # In case the citizen has the security denial enabled, address
        # information will not be sent during the authentication request.
        # In this case, the value of this attribute is '1'.
        {
          name: 'urn:oid:1.2.246.517.2002.2.27',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'TurvakieltoTieto'
        },
        #############
        ### eIDAS ###
        #############
        # NOTE:
        # The eIDAS attributes won't be sent over when the user is
        # authenticating using a Finnish authentication method.
        #
        # eIDAS personal identifier (PID)
        # eIDAS-asetuksen mukainen yksilöivä tunniste (PID)
        #
        # The format depends the issuing country and the number may be
        # e.g. attached to the identity card and change in case the card
        # is changed. The identifier is unique per person, so no two persons can
        # hold the same identifier.
        {
          name: 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'PersonIdentifier'
        },
        # Last name
        # Sukunimi
        {
          name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'FamilyName'
        },
        # Date of birth
        # Syntymäaika
        {
          name: 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'DateOfBirth'
        }
      ]

      # Maps the SAML attributes to OmniAuth info schema:
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later
      option(
        :attribute_statements,
        # Display name
        name: ['urn:oid:2.16.840.1.113730.3.1.241'],
        email: ['urn:oid:0.9.2342.19200300.100.1.3'],
        # Given name
        first_name: ['urn:oid:2.5.4.42'],
        last_name: ['urn:oid:2.5.4.4'],
        # Permanent domestic address city name in Finnish
        location: ['urn:oid:1.2.246.517.2002.2.7']
      )

      option(
        :security_settings,
        authn_requests_signed: true,
        logout_requests_signed: true,
        logout_responses_signed: true,
        want_assertions_signed: true,
        digest_method: XMLSecurity::Document::SHA256,
        signature_method: XMLSecurity::Document::RSA_SHA256
      )

      # The attribute key maps to the SAML URIs so that we have more descriptive
      # attribute keys available for use. These will be mapped to the OmniAuth
      # `extra` information hash under the `:saml_attributes` key.
      option(
        :saml_attributes_map,
        electronic_identification_number: ['urn:oid:1.2.246.22'],
        national_identification_number: ['urn:oid:1.2.246.21'],
        katso_id: ['urn:oid:1.2.246.517.3003.113.4'],
        foreign_person_identifier: ['urn:oid:1.2.246.517.3002.111.17'],
        email: ['urn:oid:0.9.2342.19200300.100.1.3'],
        common_name: ['urn:oid:2.5.4.3'],
        display_name: ['urn:oid:2.16.840.1.113730.3.1.241'],
        first_names: ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'],
        given_name: ['urn:oid:2.5.4.42'],
        last_name: ['urn:oid:2.5.4.4'],
        home_municipality_number: ['urn:oid:1.2.246.517.2002.2.18'],
        home_municipality_name_fi: ['urn:oid:1.2.246.517.2002.2.19'],
        home_municipality_name_sv: ['urn:oid:1.2.246.517.2002.2.20'],
        permanent_domestic_address_street_fi: ['urn:oid:1.2.246.517.2002.2.4'],
        permanent_domestic_address_street_sv: ['urn:oid:1.2.246.517.2002.2.5'],
        permanent_domestic_address_postal_code: ['urn:oid:1.2.246.517.2002.2.6'],
        permanent_domestic_address_locality_fi: ['urn:oid:1.2.246.517.2002.2.7'],
        permanent_domestic_address_locality_sv: ['urn:oid:1.2.246.517.2002.2.8'],
        permanent_foreign_address_street: ['urn:oid:1.2.246.517.2002.2.11'],
        permanent_foreign_address_locality_state_fi: ['urn:oid:1.2.246.517.2002.2.12'],
        permanent_foreign_address_locality_state_sv: ['urn:oid:1.2.246.517.2002.2.13'],
        permanent_foreign_address_locality_state_plain: ['urn:oid:1.2.246.517.2002.2.14'],
        permanent_foreign_address_state_code: ['urn:oid:1.2.246.517.2002.2.15'],
        temporary_domestic_address_street_fi: ['urn:oid:1.2.246.517.2002.2.31'],
        temporary_domestic_address_street_sv: ['urn:oid:1.2.246.517.2002.2.32'],
        temporary_domestic_address_postal_code: ['urn:oid:1.2.246.517.2002.2.33'],
        temporary_domestic_address_locality_fi: ['urn:oid:1.2.246.517.2002.2.34'],
        temporary_domestic_address_locality_sv: ['urn:oid:1.2.246.517.2002.2.35'],
        finnish_citizenship: ['urn:oid:1.2.246.517.2002.2.26'],
        information_security_denial: ['urn:oid:1.2.246.517.2002.2.27'],
        eidas_person_identifier: ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'],
        eidas_first_names: ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'],
        eidas_family_name: ['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'],
        eidas_date_of_birth: ['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth']
      )

      # Defines the scope of data, i.e. which attributes to fetch from the
      # Suomi.fi endpoint. Possible values are:
      # - :limited
      # - :medium_extensive
      # - :extensive
      #
      # Please refer to the documentation for more information.
      option :scope_of_data, :medium_extensive

      # Defines the attribute names for each scope.
      option(
        :scoped_attributes,
        limited: %w[
          urn:oid:1.2.246.22
          urn:oid:1.2.246.21
          urn:oid:2.5.4.3
          urn:oid:2.16.840.1.113730.3.1.241
          urn:oid:2.5.4.42
          urn:oid:2.5.4.4
          urn:oid:1.2.246.517.3003.113.4
          urn:oid:1.2.246.517.3002.111.17
          http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName
          http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier
          http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName
          http://eidas.europa.eu/attributes/naturalperson/DateOfBirth
        ],
        medium_extensive: %w[
          urn:oid:1.2.246.517.2002.2.27
          urn:oid:0.9.2342.19200300.100.1.3
          urn:oid:1.2.246.517.2002.2.18
          urn:oid:1.2.246.517.2002.2.19
          urn:oid:1.2.246.517.2002.2.20
          urn:oid:1.2.246.517.2002.2.4
          urn:oid:1.2.246.517.2002.2.5
          urn:oid:1.2.246.517.2002.2.6
          urn:oid:1.2.246.517.2002.2.7
          urn:oid:1.2.246.517.2002.2.8
          urn:oid:1.2.246.517.2002.2.11
          urn:oid:1.2.246.517.2002.2.12
          urn:oid:1.2.246.517.2002.2.13
          urn:oid:1.2.246.517.2002.2.14
          urn:oid:1.2.246.517.2002.2.15
          urn:oid:1.2.246.517.2002.2.31
          urn:oid:1.2.246.517.2002.2.32
          urn:oid:1.2.246.517.2002.2.33
          urn:oid:1.2.246.517.2002.2.34
          urn:oid:1.2.246.517.2002.2.35
        ],
        extensive: %w[urn:oid:1.2.246.517.2002.2.26]
      )

      # Salt that is used for the UID hashing. If not set, will use Rails
      # secret_key_base when under Rails. If not set and not using Rails, the
      # salt will be an empty string (not suggested).
      option :uid_salt, nil

      # Default relay state to the root path. This will redirect the logout
      # requests to the root of the application in case this configuration is
      # not overridden. Please refer to the omniauth-saml gem's documentation in
      # order to define this option.
      option :slo_default_relay_state, '/'

      # Customize the UID fetching as this has few conditions.
      #
      # The electronic identification number (sähköinen asiointitunnus, SATU) is
      # a unique electronic ID bound to the person. The ID itself does not
      # reveal any personal information of the person holding it unlike the
      # national identifiers can do.
      #
      # The SATU ID is only assigned to real people and cannot be therefore
      # determined e.g. in the Suomi.fi testing environment which is why we
      # provide a fallback using the national identifier which is always set for
      # Suomi.fi authentication requests
      #
      # For eIDAS authentications, both SATU ID and the national identifier are
      # NOT set, so in those cases we need to use the eIDAS personal identifier.
      #
      # The national identifier and eIDAS personal identifier are  hashed in
      # order to hide any personal details they are carrying (such as date of
      # birth, gender, etc.). Please provide a salt with the `uid_salt`
      # configuration option for proper hashing of the strings. For Rails, it
      # will be automatically set by
      # `Rails.application.secrets.secret_key_base`.
      #
      # Finally, fallback to the SAML NameID which is only unique per session.
      # This should not happen with any valid authentication requests.
      uid do
        electronic_id = find_attribute_by(['urn:oid:1.2.246.22'])
        national_id = find_attribute_by(['urn:oid:1.2.246.21'])
        eidas_id = find_attribute_by(
          ['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier']
        )
        hash_salt = begin
          if options.uid_salt
            options.uid_salt
          elsif defined?(::Rails) && ::Rails.application
            ::Rails.application.secrets.secret_key_base
          else
            ''
          end
        end

        if !electronic_id.nil?
          'FINUID:' + electronic_id
        elsif !national_id.nil?
          'FIHETU:' + Digest::MD5.hexdigest("FI:#{national_id}:#{hash_salt}")
        elsif !eidas_id.nil?
          'EIDASPID:' + Digest::MD5.hexdigest("EIDAS:#{eidas_id}:#{hash_salt}")
        else
          @name_id
        end
      end

      # Add the SAML attributes and the VTJ search success state to the extra
      # hash for easier access.
      extra do
        {
          search_success: search_success,
          saml_attributes: saml_attributes
        }
      end

      def initialize(app, *args, &block)
        super

        # Add the request attributes to the options.
        options[:request_attributes] = scoped_request_attributes
        options[:sp_name_qualifier] = options[:sp_entity_id] if options[:sp_name_qualifier].nil?

        # Remove the nil options from the origianl options array that will be
        # defined by the Suomi.fi options
        %i[
          certificate
          private_key
          idp_name_qualifier
          name_identifier_format
          security
        ].each do |key|
          options.delete(key) if options[key].nil?
        end

        # Add the Suomi.fi options to the local options, most of which are
        # fetched from the metadata. The options array is the one that gets
        # priority in case it overrides some of the metadata or locally defined
        # option values.
        @options = OmniAuth::Strategy::Options.new(
          suomifi_options.merge(options)
        )
      end

      # Override the request phase to be able to pass the locale parameter to
      # the redirect URL. Note that this needs to be the last parameter to
      # be passed to the redirect URL.
      def request_phase
        authn_request = OneLogin::RubySaml::Authrequest.new
        locale = locale_for_authn_request

        with_settings do |settings|
          url = authn_request.create(settings, additional_params_for_authn_request)
          url += "&locale=#{CGI.escape(locale)}" unless locale.nil?
          redirect(url)
        end
      end

      # This method can be used externally to fetch information about the
      # response, e.g. in case of failures.
      def response_object
        return nil unless request.params['SAMLResponse']

        with_settings do |settings|
          response = OneLogin::RubySaml::Response.new(
            request.params['SAMLResponse'],
            options_for_response_object.merge(settings: settings)
          )
          response.attributes['fingerprint'] = settings.idp_cert_fingerprint
          response
        end
      end

      # Override the callback URL so that it always matches the one expected by
      # Suomi.fi. No additional query string parameters can be included in the
      # string.
      def callback_url
        full_host + script_name + callback_path
      end

    private

      # Suomi.fi requires that the service provider needs to end the local user
      # session BEFORE sending the logout request to the identity provider.
      def other_phase_for_spslo
        return super unless options.idp_slo_service_url

        with_settings do |settings|
          # Some session variables are needed when generating the logout request
          request = generate_logout_request(settings)
          # Destroy the local user session
          options[:idp_slo_session_destroy].call @env, session
          # Send the logout request to the identity provider
          redirect(request)
        end
      end

      # Overridden to disable passing the relay state with a request parameter
      # which is possible in the default implementation.
      def slo_relay_state
        state = super

        # Ensure that we are only using the relay states to redirect the user
        # within the current website. This forces the relay state to always
        # start with a single forward slash character (/).
        return '/' unless state =~ %r{^/[^/].*}

        state
      end

      def scoped_request_attributes
        scopes = [:limited]
        scopes << :medium_extensive if options.scope_of_data == :medium_extensive
        scopes << :medium_extensive if options.scope_of_data == :extensive
        scopes << :extensive if options.scope_of_data == :extensive

        names = options.scoped_attributes.select do |key, _v|
          scopes.include?(key.to_sym)
        end.values.flatten

        options.possible_request_attributes.select do |attr|
          names.include?(attr[:name])
        end
      end

      def certificate
        File.read(options.certificate_file) if options.certificate_file
      end

      def private_key
        File.read(options.private_key_file) if options.private_key_file
      end

      def idp_metadata_url
        case options.mode
        when :test
          'https://static.apro.tunnistus.fi/static/metadata/idp-metadata.xml'
        else # :production
          'https://tunnistus.suomi.fi/static/metadata/idp-metadata.xml'
        end
      end

      def suomifi_options
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

        # Returns OneLogin::RubySaml::Settings prepopulated with idp metadata
        # We are using the redirect binding for the SSO and SLO URLs as these
        # are the ones expected by omniauth-saml. Otherwise the default would be
        # the first one defined in the IdP metadata, which would be the
        # HTTP-POST binding.
        settings = idp_metadata_parser.parse_remote_to_hash(
          idp_metadata_url,
          true,
          sso_binding: ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'],
          slo_binding: ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
        )

        if settings[:idp_slo_response_service_url].nil? && settings[:idp_slo_target_url].nil?
          # Mitigation after ruby-saml update to 1.12.x. This gem has been
          # originally developed relying on the `:idp_slo_target_url` settings
          # which was removed from the newer versions. The SLO requests won't
          # work unless `:idp_slo_response_service_url` is defined in the
          # metadata through the `ResponseLocation` attribute in the
          # `<SingleLogoutService />` node.
          settings[:idp_slo_target_url] ||= settings[:idp_slo_service_url]
        end

        # Local certificate and private key to decrypt the responses
        settings[:certificate] = certificate
        settings[:private_key] = private_key

        # Define the security settings as there are some defaults that need to be
        # modified
        security_defaults = OneLogin::RubySaml::Settings::DEFAULTS[:security]
        settings[:security] = security_defaults.merge(options.security_settings)

        # Add some extra information that is necessary for correctly formatted
        # logout requests.
        settings[:idp_name_qualifier] = settings[:idp_entity_id]

        settings
      end

      # This will return true if the VTJ search (population information system,
      # väestötietojärjestelmä) was successful and information about the person
      # was transmitted in the SAML response.
      def search_success
        success_string = find_attribute_by(['urn:oid:1.2.246.517.3002.111.2'])
        success_string == 'true'
      end

      def saml_attributes
        {}.tap do |attrs|
          options.saml_attributes_map.each do |target, source|
            attrs[target] = find_attribute_by(source)
          end
        end
      end

      def locale_for_authn_request
        if options.idp_sso_service_url_locale_params.is_a?(Array)
          options.idp_sso_service_url_locale_params.each do |param|
            next unless request.params.key?(param.to_s)

            locale = parse_language_value(request.params[param.to_s])
            return locale unless locale.nil?
          end
        end

        options.idp_sso_service_url_default_locale
      end

      def parse_language_value(string)
        language = string.sub('_', '-').split('-').first

        language if language =~ /^(fi|sv|en)$/
      end
    end
  end
end
