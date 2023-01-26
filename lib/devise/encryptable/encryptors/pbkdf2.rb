# frozen_string_literal: true

module Devise
  module Encryptable
    module Encryptors
      class Pbkdf2 < Base
        # Likely source of CVE(s)
        # Prevent `stretches` from being set to insecure values
        # OWASP recommendation as of 2023-01-25
        # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
        PROD = !(Rails.env.test? || Rails.env.development?)
        MIN_STRETCHES = PROD ? 600_000 : 1_000
        ENV_OVERRIDE = 'DEVISE_PBKDF2_CLAMP_STRETCHES_TO_OWASP_MINIMUM'
        ALWAYS_OVERRIDE = ENV.has_key?(ENV_OVERRIDE) # cache it for performance
        HASH = 'SHA512'
        HASH_LENGTH = OpenSSL::Digest.new(HASH).digest_length

        # Raises by default so developers are aware of app security configuration
        def self.enforce_stretches(stretches)
          return stretches if stretches.to_i >= MIN_STRETCHES
          return MIN_STRETCHES if ALWAYS_OVERRIDE
          raise ArgumentError, "stretches (#{stretches.inspec}) must be >= #{MIN_STRETCHES}, or set env var #{ENV_OVERRIDE}"
        end

        def self.compare(encrypted_password, password, stretches, salt, pepper)
          stretches = self.enforce_stretches(stretches)
          value_to_test = self.digest(password, stretches, salt, pepper)
          Devise.secure_compare(encrypted_password, value_to_test)
        end

        def self.digest(password, stretches, salt, pepper)
          stretches = self.enforce_stretches(stretches)
          OpenSSL::KDF.pbkdf2_hmac(
            password,
            salt: "#{[salt].pack('H*')}#{pepper}",
            iterations: stretches,
            hash: HASH,
            length: HASH_LENGTH,
          ).unpack1('H*')
        end
      end
    end
  end
end
