# frozen_string_literal: true

# This overrides the decryption method in RubySaml in order to add support for
# AES GCM decryption required by Suomi.fi. The Suomi.fi AES GCM cipher text
# contains an auth tag that needs to be extracted from the end of the cipher
# text before decrypting it. Otherwise the `cipher.final` method would fail
# becuse the decrypted data is incorrect.
#
# Related to this GitHub issue:
# https://github.com/onelogin/ruby-saml/issues/541
#
# This differs from the original implementation only with the following aspects:
# - Detects the AES GCM cipher methods
# - For the AES CGM cipher methods, extracts the auth tag from the end of the
#   cipher text, assuming it to be 16 bytes in length.
#
# Regarding the authentication tag, see:
# https://tools.ietf.org/html/rfc5116#section-5.1
#
# > An authentication tag with a length of 16 octets (128
# > bits) is used.  The AEAD_AES_128_GCM ciphertext is formed by
# > appending the authentication tag provided as an output to the GCM
# > encryption operation to the ciphertext that is output by that
# > operation.
OneLogin::RubySaml::Utils.class_eval do
  # Obtains the deciphered text
  # @param cipher_text [String]   The ciphered text
  # @param symmetric_key [String] The symetric key used to encrypt the text
  # @param algorithm [String]     The encrypted algorithm
  # @return [String] The deciphered text
  def self.retrieve_plaintext(cipher_text, symmetric_key, algorithm)
    case algorithm
      when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
      when 'http://www.w3.org/2009/xmlenc11#aes128-gcm' then auth_cipher = OpenSSL::Cipher.new('AES-128-GCM').decrypt
      when 'http://www.w3.org/2009/xmlenc11#aes192-gcm' then auth_cipher = OpenSSL::Cipher.new('AES-192-GCM').decrypt
      when 'http://www.w3.org/2009/xmlenc11#aes256-gcm' then auth_cipher = OpenSSL::Cipher.new('AES-256-GCM').decrypt
      when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
      when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
    end

    if cipher
      iv_len = cipher.iv_len
      data = cipher_text[iv_len..-1]
      cipher.padding, cipher.key, cipher.iv = 0, symmetric_key, cipher_text[0..iv_len-1]
      assertion_plaintext = cipher.update(data)
      assertion_plaintext << cipher.final
    elsif auth_cipher
      iv_len, text_len, tag_len = auth_cipher.iv_len, cipher_text.length, 16
      data = cipher_text[iv_len..text_len-1-tag_len]
      auth_cipher.padding = 0
      auth_cipher.key = symmetric_key
      auth_cipher.iv = cipher_text[0..iv_len-1]
      auth_cipher.auth_data = ''
      auth_cipher.auth_tag = cipher_text[text_len-tag_len..-1]
      assertion_plaintext = auth_cipher.update(data)
      assertion_plaintext << auth_cipher.final
    elsif rsa
      rsa.private_decrypt(cipher_text)
    elsif oaep
      oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    else
      cipher_text
    end
  end
end
