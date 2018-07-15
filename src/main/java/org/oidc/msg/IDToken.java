package org.oidc.msg;

import java.util.Map;

public class IDToken extends AbstractMessage {
  public IDToken() {
  }

  public IDToken(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return super.getClaims();
  }
}
