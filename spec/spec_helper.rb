# frozen_string_literal: true

require 'simplecov'
require 'omniauth-suomifi'
require 'omniauth-suomifi/test'
require 'webmock/rspec'
require 'rack/test'
require 'rexml/document'
require 'rexml/xpath'
require 'base64'

TEST_LOGGER = Logger.new(StringIO.new)
OneLogin::RubySaml::Logging.logger = TEST_LOGGER
OmniAuth.config.logger = TEST_LOGGER
OmniAuth.config.request_validation_phase = proc {}
OmniAuth.config.full_host = 'https://www.service.fi'

WebMock.disable_net_connect!(allow_localhost: true)

RSpec.configure do |config|
  config.include Rack::Test::Methods
end

def support_filepath(filename)
  File.expand_path(File.join('..', 'support', filename), __FILE__)
end

def support_file_io(filename)
  File.read(support_filepath(filename))
end

def base64_file(filename)
  Base64.encode64(support_file_io(filename))
end
