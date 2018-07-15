package org.oidc.msg;

import java.util.Map;

public class JsonResponseDescriptor extends AbstractMessage {

  public JsonResponseDescriptor() {
  }

  public JsonResponseDescriptor(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return super.getClaims();
  }
}
