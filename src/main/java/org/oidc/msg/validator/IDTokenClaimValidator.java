/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.oidc.IDToken;

/** General validator for claims type of id token. */
public class IDTokenClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (!(value instanceof IDToken)) {
      throw new InvalidClaimException(
          String.format("Parameter '%s' is not of expected type", value));
    }
    // TODO: This might not be correct phase to do verify as we might not be able to set all input
    // for verify
    if (!((IDToken) value).verify()) {
      throw new InvalidClaimException(String.format("Parameter '%s' verification failed", value));
    }
    return value;
  }
}
