package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

/**
 * Authorization Request message as described in https://tools.ietf.org/html/rfc6749 for
 * Authorization Code Grant https://tools.ietf.org/html/rfc6749#section-4.1 and Implicit Grant
 * https://tools.ietf.org/html/rfc6749#section-4.2.
 */
public class AuthorizationRequest extends AbstractMessage {
 
  /**
   * Parameter requirements.
   */
  protected final Map<String, ParameterVerificationDefinition> paramVerDefs = 
      new HashMap<String, ParameterVerificationDefinition>();

  { //Set parameter requirements for message.
    paramVerDefs.put("response_type",
        ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("client_id", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("scope", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("state", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          Authorization request claims. Expected claims are response_type(REQUIRED),
   *          client_id(REQUIRED), redirect_uri(OPTIONAL), scope (OPTIONAL) and state(RECOMMENDED).
   */
  public AuthorizationRequest(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions() {
    return paramVerDefs;
  }
}