package org.oidc.msg;

import java.util.Map;

public class RegistrationResponse extends AbstractMessage {

  public RegistrationResponse(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return null;
  }
}