package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

public class WebfingerRequest extends AbstractMessage {
  
  { //Set parameter requirements for message.
    paramVerDefs.put("resource",
        ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("rel", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    defaultValues.put("rel", "http://openid.net/specs/connect/1.0/issuer");
  }

  public WebfingerRequest() {
    this(new HashMap<String, Object>());
  }

  public WebfingerRequest(Map<String, Object> claims) {
    super(claims);
    addDefaultValues();
  }
}
