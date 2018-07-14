package org.oidc.msg;

import java.util.List;
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
   * @throws InvalidClaimException
   *           if response_type claim invalid
   */
  @SuppressWarnings("unchecked")
  public AuthenticationRequest(Map<String, Object> claims) throws InvalidClaimException {
    super(claims);
    /*
    requiredClaims.add("redirect_uri");
    requiredClaims.add("scope");
    // verify response type claim individually as it needs to be used.
    ClaimsValidator.validate("response_type", claims.get("response_type"), fetchMessageType());
    // if response type implies implicit flow, nonce is mandatory
    if (((List<String>) claims.get("response_type")).contains("id_token")
        && !((List<String>) claims.get("response_type")).contains("code")) {
      requiredClaims.add("nonce");
    
    }
    */
  }

}