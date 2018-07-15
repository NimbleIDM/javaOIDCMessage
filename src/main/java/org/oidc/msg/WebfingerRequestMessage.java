package org.oidc.msg;

import java.util.Map;

public class WebfingerRequestMessage extends AbstractMessage {
  
  { //Set parameter requirements for message.
    paramVerDefs.put("resource",
        ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("rel", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
  }
  
  public WebfingerRequestMessage() {
    super();
  }

  public WebfingerRequestMessage(Map<String, Object> claims) {
    super(claims);
  }
}
