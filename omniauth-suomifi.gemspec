# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-suomifi/version'

Gem::Specification.new do |spec|
  spec.name = 'omniauth-suomifi'
  spec.version = OmniAuth::Suomifi::VERSION
  spec.authors = ['Antti Hukkanen']
  spec.email = ['antti.hukkanen@mainiotech.fi']

  spec.summary = 'Provides a Suomi.fi strategy for OmniAuth.'
  spec.description = 'Suomi.fi e-Identification service integration for OmniAuth.'
  spec.homepage = 'https://github.com/mainio/omniauth-suomifi'
  spec.license = 'MIT'

  spec.files = Dir[
    '{lib}/**/*',
    'LICENSE',
    'Rakefile',
    'README.md'
  ]

  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth-saml', '~> 1.10.3'

  # Basic development dependencies
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.9'

  # Testing the requests
  spec.add_development_dependency 'rack-test', '~> 1.1.0'
  spec.add_development_dependency 'webmock', '~> 3.6', '>= 3.6.2'
  spec.add_development_dependency 'xmlenc', '~> 0.7.1'

  # Code coverage
  spec.add_development_dependency 'simplecov', '~> 0.19.0'
end
