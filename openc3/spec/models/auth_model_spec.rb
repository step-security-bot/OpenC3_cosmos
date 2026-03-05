# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
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

#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/models/auth_model'

module OpenC3
  describe AuthModel, type: :model do
    before(:each) do
      mock_redis()
    end

    describe "authentication" do
      it "creates new" do
        model = AuthModel.new()
        expect(model).to be_a(AuthModel)
      end

      it "self.set" do
        expect{ AuthModel.set('token1token1', nil) }.to \
          raise_error(/old_password must not be nil or empty/)

        expect{ AuthModel.set('token1token1', 'token2token2', PW_HASH_PRIMARY_KEY) }.to \
          raise_error(/old_password incorrect/)

        AuthModel.set('newpassword', AUTH_INITIAL_PASSWORD)
        expect(AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any)).to eq(false)
        expect(AuthModel.verify_no_service('newpassword', mode: :any)).to eq(true)
      end

      it "self.verify" do
        expect(AuthModel.verify('badpassword')).to eq(false)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, no_password: false)).to eq(true)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, no_password: true)).to eq(false)
      end

      it "verifies and terminates a session token" do
        token1 = AuthModel.generate_session
        token2 = AuthModel.generate_session
        expect(AuthModel.verify(token1)).to eq(true)
        expect(AuthModel.verify(token2)).to eq(true)

        # Make sure terminating one doesn't affect the other
        AuthModel.terminate(token1)
        expect(AuthModel.verify(token1)).to eq(false)
        expect(AuthModel.verify(token2)).to eq(true)
      end

      it "verifies a session token and logs out" do
        token1 = AuthModel.generate_session
        token2 = AuthModel.generate_session
        expect(AuthModel.verify(token1)).to eq(true)
        expect(AuthModel.verify(token2)).to eq(true)

        # Make sure all sessions are terminated
        AuthModel.logout
        expect(AuthModel.verify(token1)).to eq(false)
        expect(AuthModel.verify(token2)).to eq(false)
      end

      it "creates a one-time use token" do
        token = AuthModel.generate_session(otp: true)
        expect(AuthModel.verify(token)).to eq(true)

        # Already verified, second attempt shouldn't work
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "revokes all sessions on password change" do
        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)

        AuthModel.set('newpassword', AUTH_INITIAL_PASSWORD)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
  end
end
