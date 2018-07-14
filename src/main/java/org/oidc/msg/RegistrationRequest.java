package org.oidc.msg;

import java.util.List;
import java.util.Map;

public class RegistrationRequest extends AbstractMessage {

  public RegistrationRequest(Map<String, Object> claims) {
    super(claims);
  }

  /*
  @Override
  protected List<String> getRequiredClaims() {
    return null;
  }
  */

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return null;
  }

  /*
  @Override
  public MessageType fetchMessageType() {
    return MessageType.REGISTRATION_REQUEST;
  }
  */

  @Override
  public boolean allowCustomClaims() {
    return false;
  }

  @Override
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions() {
    // TODO Auto-generated method stub
    return null;
  }
}