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

/** General validator for claims type of message. */
public class MessageClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (!(value instanceof Message)) {
      throw new InvalidClaimException(
          String.format("Parameter '%s' is not of expected type", value));
    }
    // TODO: the reason for failing the verification is not carried to calling layers
    if (!((Message) value).verify()) {
      throw new InvalidClaimException(String.format("Parameter '%s' verification failed", value));
    }
    return value;
  }
}
