package org.oidc.msg;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Authentication request message as described in
 * http://openid.net/specs/openid-connect-core-1_0.html.
 */
public class AuthenticationRequest extends AuthorizationRequest {

  {
    // Updating parameter requirements.
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("scope", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("redirect_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("nonce", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("display", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("prompt", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("max_age", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("ui_locales",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("claims_locales",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("id_token_hint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("login_hint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("acr_values",
        ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    paramVerDefs.put("request", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("request_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("response_mode", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());

    // TODO: "claims"
    // paramVerDefs.put("claims", ParameterVerification.SINGLE_OPTIONAL_CLAIMSREQ.getValue());
    // TODO: Roland has this "registration" parameter, what is it?
    // paramVerDefs.put("registration", ParameterVerification.SINGLE_OPTIONAL_JSON.getValue());

    // Updating allowed values of parameters
    allowedValues.put("display", Arrays.asList("page", "popup", "touch", "wap"));
    allowedValues.put("prompt", Arrays.asList("none", "login", "consent", "select_account"));
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          Authentication request parameters. Expected claims are response_type(REQUIRED),
   *          client_id(REQUIRED), redirect_uri(REQUIRED), scope (REQUIRED), nonce
   *          (OPTIONAL/REQUIRED), state(RECOMMENDED) and other claims described in
   *          http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
   */
  public AuthenticationRequest(Map<String, Object> claims) {
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
  @SuppressWarnings("unchecked")
  public boolean verify() throws InvalidClaimException {
    super.verify();
    // TODO:Verify "request" is formed correctly if it exists..
    // Create OpenIDRequest message class, decode it from JWT. It should check the signature
    // Check that fields match -> ValueError
    // TODO:Verify "id_token_hint" if it exists..
    // Use IdToken, decode it from JWT. It should check the signature
    // TODO:if implicit flow (or also hybrid?), check for existence of nonce
    // TODO: what is the following ''Nonce in id_token not matching nonce in authz'
    
    String spaceSeparatedScopes = ((String) getClaims().get("scope"));
    
    if (spaceSeparatedScopes == null
        || !Pattern.compile("\\bopenid\\b").matcher(spaceSeparatedScopes).find()) {
      getError().getMessages().add("Parameter scope must exist and contain value openid");
    }
    
    List<String> prompt = ((List<String>) getClaims().get("prompt"));
    
    if (prompt != null && prompt.contains("none") && prompt.size() > 1) {
      getError().getMessages().add("prompt value none must not be used with other values");
    }
    
    if (Pattern.compile("\\boffline_access\\b").matcher(spaceSeparatedScopes).find()) {
      if (prompt == null || !prompt.contains("consent")) {
        getError().getMessages()
            .add("When offline_access scope is used prompt must have value consent");
      }
    }

    if (getError().getMessages().size() > 0) {
      this.setVerified(false);
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    return hasError();
  }

}