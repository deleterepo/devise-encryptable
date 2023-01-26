require 'scrypt'

module Devise
  module Encryptable
    module Encryptors
      class Scrypt < Base
        def self.compare(expected_encrypted_password, plaintext_password_given, _stretches, _salt, pepper)
          ::SCrypt::Password.new(expected_encrypted_password) == "#{plaintext_password_given}#{salt}#{pepper}"
        end

        def self.digest(password, _stretches, salt, pepper)
          ::SCrypt::Password.create("#{password}#{salt}#{pepper}")
        end
      end
    end
  end
