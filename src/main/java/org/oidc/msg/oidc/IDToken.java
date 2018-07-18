package org.oidc.msg.oidc;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;

/** ID Token as in http://openid.net/specs/openid-connect-core-1_0.html#IDToken. */
public class IDToken extends OpenIDSchema {

  {
    // Updating parameter requirements.
    paramVerDefs.put("iss", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("sub", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("aud", ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("exp", ParameterVerification.SINGLE_REQUIRED_INT.getValue());
    paramVerDefs.put("iat", ParameterVerification.SINGLE_REQUIRED_INT.getValue());
    paramVerDefs.put("auth_time", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("nonce", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("at_hash", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("c_hash", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("acr", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("amr", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("azp", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("sub_jwk", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());

  }

  /**
   * Constructor.
   */
  public IDToken() {
    this(new HashMap<String, Object>());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          ID Token claims as described in
   *          http://openid.net/specs/openid-connect-core-1_0.html#IDToken.
   */
  public IDToken(Map<String, Object> claims) {
    super(claims);
  }

  /**
   * Verifies the presence of required message parameters. Verifies the the format of message
   * parameters.
   * 
   * @return true if parameters are successfully verified.
   * @throws InvalidClaimException
   *           if verification fails.
   */
  public boolean verify() throws InvalidClaimException {
    super.verify();
    // TODO:Check issuer. Requires setter for issuer to compare against.
    // TODO:Check client_id is among aud. Requires a setter for client_id to compare against.
    // TODO:if multiple aud, check azp is in audience.
    // TODO:if client_id is set and azp exists, they must match.
    // TODO:check exp is not in the past. Requires setter for skew to allow skew.
    // TODO:check iat+NONCE_STORAGE_TIME < now - skew. Requires setter but leave it until
    // requirement is clear. NONCE_STORAGE_TIME = 4 * 3600
    // TODO: Check nonce. Requires setter for nonce to compare against.
    return true;

  }
}
