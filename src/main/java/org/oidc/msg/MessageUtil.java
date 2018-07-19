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

package org.oidc.msg;

import com.auth0.jwt.exceptions.JWTDecodeException;

import java.util.HashMap;
import java.util.Map;

public class MessageUtil {
  /**
   * Returns a hashmap representation of the contents of the urlEncoded string which is passed in as
   * a parameter
   *
   * @param urlEncoded
   *          the urlEncoded String representation of a message
   * @return a map of the key value pairs encoded in the string parameter
   */
  private Map<String, Object> claims;

  public MessageUtil(Map<String, Object> claims) {
    this.claims = claims;
  }

  public static Map<String, Object> claimsFromUrlEncoded(String urlEncoded) throws Exception {
    // Logic to extract from the string the values
    Map<String, Object> values = new HashMap<String, Object>();
    return values;
  }

  public Map<String, Object> getClaims() {
    return this.claims;
  }

  /**
   * @param String
   *          endpoint to base the request url on
   * @return a String for the representation of the formatted request
   */
  public String getRequestWithEndpoint(String authorizationEndpoint) {
    return null;
  }

  /**
   * Splits the given token on the "." chars into a String array with 3 parts.
   *
   * @param token
   *          the string to split.
   * @return the array representing the 3 parts of the token.
   * @throws JWTDecodeException
   *           if the Token doesn't have 3 parts.
   */
  static String[] splitToken(String token) throws JWTDecodeException {
    String[] parts = token.split("\\.");
    if (parts.length == 2 && token.endsWith(".")) {
      // Tokens with alg='none' have empty String as Signature.
      parts = new String[] { parts[0], parts[1], "" };
    }
    if (parts.length != 3) {
      throw new JWTDecodeException(
          String.format("The token was expected to have 3 parts, but got %s.", parts.length));
    }
    return parts;
  }
}
