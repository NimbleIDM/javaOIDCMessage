package org.oidc.msg;

import java.util.Map;

public class WebfingerRequestMessage extends AbstractMessage {
  public WebfingerRequestMessage() {
  }

  public WebfingerRequestMessage(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return super.getClaims();
  }

  @Override
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions() {
    // TODO Auto-generated method stub
    return null;
  }
}
