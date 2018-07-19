package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.oauth2.ResponseMessage;

public class RegistrationResponse extends ResponseMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("client_id", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("client_secret", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("registration_access_token",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("registration_client_uri",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("client_id_issued_at", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    paramVerDefs.put("client_secret_expires_at",
        ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    // copy all the values from registration request
    paramVerDefs.putAll(new RegistrationRequest().getParameterVerificationDefinitions());
  }

  public RegistrationResponse() {
    this(new HashMap<String, Object>());
  }

  public RegistrationResponse(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public boolean verify() throws InvalidClaimException {
    boolean verify = false;
    try {
      verify = super.verify();
    } catch (InvalidClaimException e) {
      // carry on, possibly populate more error messages
    }
    boolean hasRegUri = getClaims().containsKey("registration_client_uri");
    boolean hasRegAt = getClaims().containsKey("registration_access_token");
    if (hasRegUri != hasRegAt) {
      error.getMessages()
          .add("Only one of registration_client_uri and registration_access_token present");
    }
    if (error.getMessages().size() > 0) {
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    return verify;
  }
}