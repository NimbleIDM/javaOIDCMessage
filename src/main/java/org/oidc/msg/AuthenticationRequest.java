package org.oidc.msg;

import java.util.Map;

/**
 * Authentication request message as described in
 * http://openid.net/specs/openid-connect-core-1_0.html.
 */
public class AuthenticationRequest extends AuthorizationRequest {

  { //Updating AuthorizationRequest parameter requirements.
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("scope", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
  }
  
  /**
   * Constructor.
   * 
   * @param claims
   *          Authentication request claims. Expected claims are response_type(REQUIRED),
   *          client_id(REQUIRED), redirect_uri(REQUIRED), scope (REQUIRED), nonce
   *          (OPTIONAL/REQUIRED), state(RECOMMENDED) and other claims described in
   *          http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
   */
  public AuthenticationRequest(Map<String, Object> claims) {
    super(claims);
    
  }

}