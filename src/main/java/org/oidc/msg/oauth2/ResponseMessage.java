package org.oidc.msg.oauth2;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.ParameterVerification;

/**
 * The base OAuth2 response message containing optional error parameters.
 */
public class ResponseMessage extends AbstractMessage {

  { //Set parameter requirements for message.
    paramVerDefs.put("error", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("error_description", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("error_uri", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
  }
  
  public ResponseMessage() {
    this(new HashMap<String, Object>());
  }
  
  public ResponseMessage(Map<String, Object> claims) {
    super(claims);
  }
}
