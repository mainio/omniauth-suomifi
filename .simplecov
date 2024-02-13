# frozen_string_literal: true

SimpleCov.start do
  root ENV.fetch('ENGINE_ROOT', nil)

  add_filter 'lib/omniauth-suomifi/version.rb'
  add_filter '/spec'
end

SimpleCov.command_name ENV['COMMAND_NAME'] || File.basename(Dir.pwd)

SimpleCov.merge_timeout 1800

if ENV['CI']
  require 'simplecov-cobertura'
  SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter
end
