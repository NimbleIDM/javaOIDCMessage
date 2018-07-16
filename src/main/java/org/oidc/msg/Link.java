package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

/**
 * One of the attributes of JSON Resource Description (JRD) Contains these attributes: rel, type,
 * href, titles, and properties For more info, please see:
 * https://tools.ietf.org/html/rfc7033#section-4.4.4
 */
public class Link extends AbstractMessage {

  { //Set parameter requirements for message.
    paramVerDefs.put("rel", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("type", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("href", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("titles", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
    paramVerDefs.put("properties", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
  }
  
  public Link() {
    this(new HashMap<String, Object>());
  }
  
  public Link(Map<String, Object> claims) {
    super(claims);
  }
}
