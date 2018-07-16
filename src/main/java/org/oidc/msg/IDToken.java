package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

public class IDToken extends AbstractMessage {
  
  public IDToken() {
    this(new HashMap<String, Object>());
  }

  public IDToken(Map<String, Object> claims) {
    super(claims);
  }
}
