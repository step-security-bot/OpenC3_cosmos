/*
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
*/

import { Api } from '.'
import { createConsumer } from '@anycable/web'

export default class Cable {
  constructor(url = '/openc3-api/cable', otpUrl = '/openc3-api/auth/otp') {
    this._cable = null
    this._url = url
    this._otpUrl = otpUrl
  }
  disconnect() {
    if (this._cable) {
      this._cable.cable.disconnect()
      this._cable = null
    }
  }
  createSubscription(channel, scope, callbacks = {}, additionalOptions = {}) {
    return OpenC3Auth.updateToken(OpenC3Auth.defaultMinValidity)
      .then((refreshed) => {
        if (refreshed) {
          OpenC3Auth.setTokens()
        }
        return Api.get(this._otpUrl, {
          params: {
            scope,
          },
        })
      })
      .then(({ data: otp }) => {
        if (this._cable == null) {
          const finalUrl = new URL(this._url, document.baseURI)
          finalUrl.searchParams.set('scope', scope)
          finalUrl.searchParams.set('authorization', otp)
          this._cable = createConsumer(finalUrl.href)
        }
        return this._cable.subscriptions.create(
          {
            channel,
            ...additionalOptions,
          },
          callbacks,
        )
      })
  }
  recordPing() {
    // Noop with Anycable
  }
}
