# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is free software; you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'digest'
require 'securerandom'
require 'openc3/utilities/store'

module OpenC3
  class AuthModel
    PRIMARY_KEY = 'OPENC3__TOKEN'
    SESSIONS_KEY = 'OPENC3__SESSIONS'

    TOKEN_CACHE_TIMEOUT = 5
    SESSION_CACHE_TIMEOUT = 5
    @@token_cache = nil
    @@token_cache_time = nil
    @@session_cache = nil
    @@session_cache_time = nil

    MIN_TOKEN_LENGTH = 8

    def self.set?(key = PRIMARY_KEY)
      Store.exists(key) == 1
    end

    def self.verify(token)
      # Handle a service password - Generally only used by ScriptRunner
      # TODO: Replace this with temporary service tokens
      service_password = ENV['OPENC3_SERVICE_PASSWORD']
      return true if service_password and service_password == token

      return false if service_only

      mode = no_password ? :token : :any
      return verify_no_service(token, mode: mode)
    end

    # Checks whether the provided token is a valid user password or session token.
    # @param token [String] the plaintext password or session token to check (required)
    # @param mode [String] optionally restrict verification to just the password or token. Valid values: :password, :token, or :any (default :token)
    # @return [Boolean] whether the provided password/token is valid
    def self.verify_no_service(token, mode: :token)
      modes = [:password, :token, :any]
      raise ArgumentError, "Invalid mode '#{mode}': must be one of #{modes}" unless modes.include?(mode)

      return false if token.nil? or token.empty?

      time = Time.now
      unless mode == :password
        return true if @@session_cache and (time - @@session_cache_time) < SESSION_CACHE_TIMEOUT and @@session_cache[token]

        # Check stored session tokens
        @@session_cache = Store.hgetall(SESSIONS_KEY)
        @@session_cache_time = time
        return true if @@session_cache[token]
      end

      unless mode == :token
        return true if @@pw_hash_cache and (time - @@pw_hash_cache_time) < PW_HASH_CACHE_TIMEOUT and Argon2::Password.verify_password(token, @@pw_hash_cache)

        # Check stored password hash
        pw_hash = Store.get(PRIMARY_KEY)
        raise "invalid password hash" if pw_hash.nil? || !pw_hash.start_with?("$argon2") # Catch users who didn't run the migration utility when upgrading to COSMOS 7
        @@pw_hash_cache = pw_hash
        @@pw_hash_cache_time = time
        return true if Argon2::Password.verify_password(token, @@pw_hash_cache)
      end

      return false
    end

    def self.set(token, old_token, key = PRIMARY_KEY)
      raise "token must not be nil or empty" if token.nil? or token.empty?
      raise "token must be at least 8 characters" if token.length < MIN_TOKEN_LENGTH

      if set?(key)
        raise "old_password must not be nil or empty" if old_password.nil? or old_password.empty?
        raise "old_password incorrect" unless verify_no_service(old_password, mode: :password)
      end
      pw_hash = Argon2::Password.create(password, profile: ARGON2_PROFILE)
      Store.set(key, pw_hash)
      @@pw_hash_cache = nil
      @@pw_hash_cache_time = nil
      logout
    end

    def self.generate_session
      token = SecureRandom.urlsafe_base64(nil, false)
      Store.hset(SESSIONS_KEY, token, Time.now.iso8601)
      return token
    end

    def self.logout
      Store.del(SESSIONS_KEY)
      @@sessions_cache = nil
      @@sessions_cache_time = nil
    end

    def self.hash(token)
      Digest::SHA2.hexdigest token
    end
  end
end
