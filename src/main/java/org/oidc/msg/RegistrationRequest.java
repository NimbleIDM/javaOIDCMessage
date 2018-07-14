package org.oidc.msg;

import java.util.Map;

public class RegistrationRequest extends AbstractMessage {

  public RegistrationRequest(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return null;
  }

  @Override
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions() {
    return null;
  }
}