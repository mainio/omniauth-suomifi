# OmniAuth Suomi.fi

This is an unofficial OmniAuth strategy for authenticating with the Suomi.fi
e-Identification service. This is mostly a configuration wrapper around
[`omniauth-saml`](https://github.com/omniauth/omniauth-saml) which uses
[`ruby-saml`](https://github.com/onelogin/ruby-saml) for SAML 2.0 based
authentication implementation with identity providers, such as Suomi.fi.

The gem can be used to hook Ruby/Rails applications to the Suomi.fi
e-Identification service. It does not provide any strong authorization features
out of the box, as it does not know anything about the application users, but
those can be implemented using this gem and the data provided by the Suomi.fi
identification responses.

The gem has been developed by [Mainio Tech](https://www.mainiotech.fi/).

The development has been sponsored by the
[City of Helsinki](https://www.hel.fi/).

The Population Register Centre (VRK) or the Suomi.fi maintainers are not related
to this gem in any way, nor do they provide technical support for it. Please
contact the gem maintainers in case you find any issues with it.

## Preparation

### Permit and Legal Basis for Using Suomi.fi e-Identification

Suomi.fi requires all its users to apply for a permit to use the
e-Identification system. All production users need to have a legal basis for
using the Suomi.fi e-Identification.

The legal basis are defined in 5 § of the "Laki hallinnon yhteisistä sähköisen
asioinnin tukipalveluista" law. Please read further from Finlex:

https://www.finlex.fi/fi/laki/alkup/2016/20160571#Pidp448960448

You are allowed use the Suomi.fi e-Identification system's testing enviroment
for testing and development purposes also when you do not have a legal basis for
using it in production.

Please reserve enough time for applying the permit to use the service and plan
the introduction of the feature accordingly.

### Join Suomi.fi Service Management

Create a Suomi.fi Service Management account at:

https://palveluhallinta.suomi.fi

After signing up, make sure your user has "edit" rights for the e-Identification
service. More about managing user rigts (in Finnish):

https://palveluhallinta.suomi.fi/fi/tuki/artikkelit/59ddee7381d2f300670b9597

### Define the Scope of Data

Each service needs to define the scope of data and reason why they need specific
information about the identified users in case they need more than the basic
details.

The scopes of data are limited (suppea), medium-extensive (keskilaaja) and
extensive (laaja). The following list describes which information is provided
with each of these scopes, starting from the limited scope:

- No scope required (included with the "Limited" scope)
  * Katso-ID (`:katso_id`), only when identifying using a Katso-ID
  * Foreign person identifier (`:foreign_person_identifier`)
  * eIDAS person identifier (`:eidas_person_identifier`)
  * eIDAS first names (`:eidas_first_names`)
  * eIDAS family names (`:eidas_family_name`)
  * eIDAS date of birth (`:eidas_date_of_birth`)
- Limited
  * Electronic identification number (`:electronic_identification_number`)
  * National identification number (`:national_identification_number`)
  * Full "common" name (`:common_name`)
  * Display name (`:display_name`)
  * First names (`:first_names`)
  * Last name / family name (`:last_name`)
- Medium-extensive
  * Email address (`:email`)
  * Home municipality number (`:home_municipality_number`)
  * Home municipality name in Finnish (`:home_municipality_name_fi`)
  * Home municipality name in Swedish (`:home_municipality_name_sv`)
  * Address information
    - Permanent domestic address (`:permanent_domestic_address_street_fi`,
      `:permanent_domestic_address_street_sv`,
      `:permanent_domestic_address_postal_code`,
      `:permanent_domestic_address_locality_fi`,
      `:permanent_domestic_address_locality_sv`)
    - Permanent foreign address (`:permanent_foreign_address_street`,
      `:permanent_foreign_address_locality_state_fi`,
      `:permanent_foreign_address_locality_state_sv`,
      `:permanent_foreign_address_locality_state_plain`,
      `:permanent_foreign_address_state_code`)
    - Temporary domestic address (`:temporary_domestic_address_street_fi`,
      `:temporary_domestic_address_street_sv`,
      `:temporary_domestic_address_postal_code`,
      `:temporary_domestic_address_locality_fi`,
      `:temporary_domestic_address_locality_sv`)
  * Information security denial (`:information_security_denial`)
- Extensive
  * Finnish citizenship information (`:finnish_citizenship`)

With the more extensive scopes, also the information in the less extensive
scopes are included.

### Prepare the Metadata

Create a certificate that you will need for the Suomi.fi metadata. For example,
the following command would create a self signed certificate that is valid for
10 years:

```
$ openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 \
  -keyout private.key -out certificate.crt
```

For production environments, you will need a certificate signed by a trusted CA
and it should not be the same one you use for the test environment.

Then download the sample metadata from Suomi.fi in order to prepare it according
to your environment. You will find this from the service management panel of
Suomi.fi.

Change at least the following information in the sample metadata:

- Define the `entityID` attribute for the EntityDescriptor element. This can
  be e.g. `https://test.city.fi/users/auth/suomifi/metadata`
- Paste the certificate you created above to the corresponding certificate
  element inside the `KeyDescriptor` element.
- Change the SAML URLs as follows:
  * `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test.city.fi/users/auth/suomifi/slo"/>`
  * `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://test.city.fi/users/auth/suomifi/slo"/>`
  * `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://test.city.fi/users/auth/suomifi/callback" index="1" isDefault="true"/>`
- Define the scope of data according to your requirements and the instructions
  in the Suomi.fi service management panel.
- Fill in all other missing details marked with `TODO`, such as service name,
  description, links and logo. Refer to the Suomi.fi's own documentation for
  more information.

Note that you will need to use the HTTPS URLs in your application's return URLs
because otherwise the Suomi.fi endpoints will not work. The testing mode and the
Suomi.fi testing endpoints will work correctly also using the unsecured HTTP
URLs.

### Register the Service and Send the Metadata

Sign in to Suomi.fi Service Management and register the new service there for
testing purposes. Submit the metadata through the service registration section.

Suomi.fi maintainers will check the metadata and will approve it for test use
in case everything is OK with the data. This will take some time to complete as
it needs manual interaction from the Suomi.fi maintainers.

## Installation and Configuration

This gem has been only tested and used with Rails applications using Devise, so
this installation guide only covers that part. In case you are interested to
learn how you can use this with other frameworks, please refer to the
[`omniauth-saml`](https://github.com/omniauth/omniauth-saml) documentation and
apply it to your needs (changing the strategy name to `:suomifi` and strategy
class to `OmniAuth::Strategies::Suomifi`).

To install this gem, add the following to your Gemfile:

```ruby
gem 'omniauth-suomifi'
```

For configuring the strategy for Devise, add the following in your
`config/initializers/devise.rb` file:

```ruby
# Define the path where you have stored the certificate files.
cert_path = "/path/to/certificates/you/created"

Devise.setup do |config|
  config.omniauth :suomifi,
    # The mode needs to be either :production or :test depending on which
    # Suomi.fi enviroment you want to hook into. Please note that you will need
    # to complete most of the preparation phases even for the test environment.
    mode: :test, # :production (default, can be omitted) or :test
    # This can be :limited, :medium_extensive or :extensive depending on your
    # needs. Refer to the documentation for more information.
    scope_of_data: :medium_extensive,
    # The service provider entity ID that needs to match the metadata sent to
    # Suomi.fi.
    sp_entity_id: 'https://www.service.fi/users/auth/suomifi/metadata',
    # The certificate and its corresponding private key. The certificate (public
    # part) needs to be provided to Suomi.fi as part of the metadata.
    certificate_file: "#{cert_path}/certificate.crt",
    private_key_file: "#{cert_path}/private.key"
end
```

## Identification Responses

The user's data is transmitted from Suomi.fi in the SAML authentication
response. This data will be available in the OmniAuth
[extra hash](https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later).

In order to access the response data, you can fetch the OmniAuth extra has and
the corresponding user data in the OmniAuth callback handler, e.g. in Rails
Devise controllers as follows:

```ruby
def saml_attributes
  raw_hash = request.env["omniauth.auth"]
  extra_hash = raw_hash[:extra]

  # :saml_attributes contains the user's data.
  # :search_success defines whether the user data was queried correctly.
  extra_hash[:saml_attributes] if extra_hash[:search_success]
end
```

### Population Information System Search Success State

When identifying the users with the Suomi.fi e-Identification service, the
identity provider will do an external query to the population information system
about the user to fetch their personal information. In some special occasions,
this query can fail in which case the user's personal information is not
transmitted in the SAML response.

To determine whether the search was successful or not, you can fetch the
`:search_success` key from the OmniAuth extra hash. This contains a boolean
value indicating whether the search was successful or not.

This information is transmitted as a SAML attribute in the authentication
response with the name `urn:oid:1.2.246.517.3002.111.2`.

### Personal Information Transmitted From Suomi.fi

The user's personal information transmitted from Suomi.fi can be found under
the `:saml_attributes` key in the OmniAuth extra hash described above.

This attributes hash will contain the keys described in this following
sub-sections.

Scopes of data, according to the requested scope when registering the service
with Suomi.fi:

- Limited (suppea)
- Medium-extensive (keskilaaja)
- Extensive (laaja)

#### `:electronic_identification_number`

- SAML URI: urn:oid:1.2.246.22
- SAML FriendlyName: electronicIdentificationNumber
- Scope of data: Limited

The electronic identification number (sähköinen asiointitunnus, SATU/FINUID) is
a unique electronic ID bound to the person. The ID itself does not reveal any
personal information of the person holding it unlike the national identifiers
can do.

This number is only assigned to real people and cannot be therefore determined
e.g. in the Suomi.fi testing environment. Also the non-person identities (such
as organizations) may not always hold this information.

More information available at:

https://vrk.fi/sahkoinen-henkilollisyys-ja-varmenteet

https://vrk.fi/en/electronic-identity-and-certificates

#### `:national_identification_number`

- SAML URI: urn:oid:1.2.246.21
- SAML FriendlyName: nationalIdentificationNumber
- Scope of data: Limited

The national identification number (henkilötunnus, HETU) which identifies the
Finnish citizen.

#### `:katso_id`

- SAML URI: urn:oid:1.2.246.517.3003.113.4
- SAML FriendlyName: kid
- Scope of data: Not required

User ID bound to the Katso-ID which is used to identify organizations, such as
businesses. Will not be set unless the user identifies themselves using the
Katso-ID.

More information available at:

https://vrk.fi/katso-tunnistus1

https://yritys.tunnistus.fi/

#### `:foreign_person_identifier`

- SAML URI: urn:oid:1.2.246.517.3002.111.17
- SAML FriendlyName: foreignpersonIdentifier
- Scope of data: Not defined

In case the person is identifying themselves using a foreign identity provider,
they have a foreign person identifier. This matches the
`:eidas_person_identifier` attribute when set.

#### `:email`

- SAML URI: urn:oid:0.9.2342.19200300.100.1.3
- SAML FriendlyName: mail
- Scope of data: Medium-extensive

The email address of the person in case it is stored in the Population Register
Centre database.

#### `:common_name`

- SAML URI: urn:oid:2.5.4.3
- SAML FriendlyName: cn
- Scope of data: Limited

The name of the person formatted as last name + all first names. In case the
identified entity is using a Katso-ID, contains the name of the identified
entity, e.g. the organization name.

Example:
Suomalainen Sari Säde

#### `:display_name`

- SAML URI: urn:oid:2.16.840.1.113730.3.1.241
- SAML FriendlyName: displayName
- Scope of data: Limited

The display name of the person formatted as given name + last name. This is the
format of the name that is most commonly used in real life.

Example:
Sari Suomalainen

#### `:first_names`

- SAML URI: http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName
- SAML FriendlyName: FirstName
- Scope of data: Limited

All first names of the person separated with a space character.

Example:
Sari Säde

#### `:given_name`

- SAML URI: urn:oid:2.5.4.42
- SAML FriendlyName: givenName
- Scope of data: Limited

The given name of the person, i.e. the first name of the person that is
generally used when referring to the person. Also known as "calling name"
("kutsumanimi" in Finnish).

Example:
Sari

#### `:last_name`

- SAML URI: urn:oid:2.5.4.4
- SAML FriendlyName: sn
- Scope of data: Limited

The last name or the family name of the person.

Example:
Suomalainen

#### `:home_municipality_number`

- SAML URI: urn:oid:1.2.246.517.2002.2.18
- SAML FriendlyName: KotikuntaKuntanumero
- Scope of data: Medium-extensive

The number of the home locality (municipality) of the person.

These numbers are defined at:

http://tilastokeskus.fi/meta/luokitukset/kunta/001-2017/index.html

http://tilastokeskus.fi/meta/luokitukset/kunta/001-2017/index_en.html

#### `:home_municipality_name_fi`

- SAML URI: urn:oid:1.2.246.517.2002.2.19
- SAML FriendlyName: KotikuntaKuntaS
- Scope of data: Medium-extensive

The name of the home locality (municipality) in Finnish.

#### `:home_municipality_name_sv`

- SAML URI: urn:oid:1.2.246.517.2002.2.20
- SAML FriendlyName: KotikuntaKuntaR
- Scope of data: Medium-extensive

The name of the home locality (municipality) in Swedish.

#### `:permanent_domestic_address_street_fi`

- SAML URI: urn:oid:1.2.246.517.2002.2.4
- SAML FriendlyName: VakinainenKotimainenLahiosoiteS
- Scope of data: Medium-extensive

Street address (street name in Finnish) of the person's permanent domestic
address.

This contains the street name in Finnish, the street number of the building and
the apartment number in case of an apartment building.

Example:
Veneentekijäntie 4 A62

Maximum of 100 characters.

#### `:permanent_domestic_address_street_sv`

- SAML URI: urn:oid:1.2.246.517.2002.2.5
- SAML FriendlyName: VakinainenKotimainenLahiosoiteR
- Scope of data: Medium-extensive

Street address (street name in Swedish) of the person's permanent domestic
address.

Same as `:permanent_domestic_address_street_fi` but the street name is in
Swedish.

Example:
Båtbyggarvägen 4 A62

#### `:permanent_domestic_address_postal_code`

- SAML URI: urn:oid:1.2.246.517.2002.2.6
- SAML FriendlyName: VakinainenKotimainenLahiosoitePostinumero
- Scope of data: Medium-extensive

Postal code (street name in Swedish) of the person's permanent domestic address.

More information available at:

https://www.tilastokeskus.fi/tup/karttaaineistot/postinumeroalueet.html

#### `:permanent_domestic_address_locality_fi`

- SAML URI: urn:oid:1.2.246.517.2002.2.7
- SAML FriendlyName: VakinainenKotimainenLahiosoitePostitoimipaikkaS
- Scope of data: Medium-extensive

The locality name (in Finnish) of the person's permanent domestic address. This
is either city or municipality name.

#### `:permanent_domestic_address_locality_sv`

- SAML URI: urn:oid:1.2.246.517.2002.2.8
- SAML FriendlyName: VakinainenKotimainenLahiosoitePostitoimipaikkaR
- Scope of data: Medium-extensive

The locality name (in Swedish) of the person's permanent domestic address. This
is either city or municipality name.

#### `:permanent_foreign_address_street`

- SAML URI: urn:oid:1.2.246.517.2002.2.11
- SAML FriendlyName: VakinainenKotimainenLahiosoiteS
- Scope of data: Medium-extensive

Street address of the person's permanent foreign address.

#### `:permanent_foreign_address_locality_state_fi`

- SAML URI: urn:oid:1.2.246.517.2002.2.12
- SAML FriendlyName: VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioS
- Scope of data: Medium-extensive

The postal code, locality name and state name (in Finnish) of the person's
permanent foreign address. The state name is separated with a comma from the
locality and postal code.

This element has information only when the person's state code is available in
the ISO 3166 standard.

#### `:permanent_foreign_address_locality_state_sv`

- SAML URI: urn:oid:1.2.246.517.2002.2.13
- SAML FriendlyName: VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioR
- Scope of data: Medium-extensive

Same as `:permanent_foreign_address_locality_state_fi` but the state name is
in Swedish.

#### `:permanent_foreign_address_locality_state_plain`

- SAML URI: urn:oid:1.2.246.517.2002.2.14
- SAML FriendlyName: VakinainenUlkomainenLahiosoitePaikkakuntaJaValtioSelvakielinen
- Scope of data: Medium-extensive

In case the person's permanent foreign address state is not available in the
ISO 3166 standard, the address will be set in this attribute in plain text
format.

This is only set in case `:permanent_foreign_address_locality_state_fi` and
`:permanent_foreign_address_locality_state_sv` are empty.

#### `:permanent_foreign_address_state_code`

- SAML URI: urn:oid:1.2.246.517.2002.2.15
- SAML FriendlyName: VakinainenUlkomainenLahiosoiteValtiokoodi
- Scope of data: Medium-extensive

The state code (ISO 3166) of the person's permanent foreign address.

#### `:temporary_domestic_address_street_fi`

- SAML URI: urn:oid:1.2.246.517.2002.2.31
- SAML FriendlyName: TilapainenKotimainenLahiosoiteS
- Scope of data: Medium-extensive

Street address (street name in Finnish) of the person's temporary domestic
address.

This contains the street name in Finnish, the street number of the building and
the apartment number in case of an apartment building.

Example:
Veneentekijäntie 4 A62

Maximum of 100 characters.

#### `:temporary_domestic_address_street_sv`

- SAML URI: urn:oid:1.2.246.517.2002.2.32
- SAML FriendlyName: TilapainenKotimainenLahiosoiteR
- Scope of data: Medium-extensive

Street address (street name in Swedish) of the person's permanent domestic
address.

Same as `:temporary_domestic_address_street_fi` but the street name is in
Swedish.

Example:
Båtbyggarvägen 4 A62

#### `:temporary_domestic_address_postal_code`

- SAML URI: urn:oid:1.2.246.517.2002.2.33
- SAML FriendlyName: TilapainenKotimainenLahiosoitePostinumero
- Scope of data: Medium-extensive

Postal code (street name in Swedish) of the person's temporary domestic address.

More information available at:

https://www.tilastokeskus.fi/tup/karttaaineistot/postinumeroalueet.html

#### `:temporary_domestic_address_locality_fi`

- SAML URI: urn:oid:1.2.246.517.2002.2.34
- SAML FriendlyName: TilapainenKotimainenLahiosoitePostitoimipaikkaS
- Scope of data: Medium-extensive

The locality name (in Finnish) of the person's temporary domestic address. This
is either city or municipality name.

#### `:temporary_domestic_address_locality_sv`

- SAML URI: urn:oid:1.2.246.517.2002.2.35
- SAML FriendlyName: TilapainenKotimainenLahiosoitePostitoimipaikkaR
- Scope of data: Medium-extensive

The locality name (in Swedish) of the person's temporary domestic address. This
is either city or municipality name.

#### `:finnish_citizenship`

- SAML URI: urn:oid:1.2.246.517.2002.2.26
- SAML FriendlyName: SuomenKansalaisuusTietokoodi
- Scope of data: Extensive

Information whether the person is Finnish citizen. The value is `1` in case the
person is a Finnish citizen.

#### `:information_security_denial`

- SAML URI: urn:oid:1.2.246.517.2002.2.27
- SAML FriendlyName: Turvakielto
- Scope of data: Medium-extensive

Information whether the person has set an information security denial for the
Population Register Centre for providing their information to third parties. In
case this is the case, the value of this attribute will be `1`.

In case the information security denial is set, the address information will not
be transmitted over to the application with the identity response.

#### `:eidas_person_identifier`

- SAML URI: http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier
- SAML FriendlyName: PersonIdentifier
- Scope of data: Not defined

A person identifier according to the eIDAS regulation. The format depends the
issuing country and the number may be e.g. attached to the identity card and
change in case the card is changed. The identifier is unique per person, so no
two persons can hold the same identifier.

Only set for person identifying themselves using an eIDAS identity provider.

#### `:eidas_first_names`

- SAML URI: http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName
- SAML FriendlyName: FirstName
- Scope of data: Not defined

The same as `:first_names`. Duplicated for clarity that this attribute is passed
along with the other eIDAS attributes.

Only set for person identifying themselves using an eIDAS identity provider.

#### `:eidas_family_name`

- SAML URI: http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName
- SAML FriendlyName: FamilyName
- Scope of data: Not defined

The eIDAS family name of the person.

Only set for person identifying themselves using an eIDAS identity provider.

#### `:eidas_date_of_birth`

- SAML URI: http://eidas.europa.eu/attributes/naturalperson/DateOfBirth
- SAML FriendlyName: DateOfBirth
- Scope of data: Not defined

The eIDAS date of birth of the person.

Only set for person identifying themselves using an eIDAS identity provider.

## License

MIT, see [LICENSE](LICENSE).
