package org.oidc.msg;

import java.util.List;
import java.util.Map;

public class IDToken extends AbstractMessage {
  public IDToken() {
  }

  public IDToken(Map<String, Object> claims) {
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
    return super.getClaims();
  }

  /*
  @Override
  public MessageType fetchMessageType() {
    return MessageType.ID_TOKEN;
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
