package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.validator.LinksClaimValidator;

/**
 * JSON Resource Descriptor https://tools.ietf.org/html/rfc7033#section-4.4
 */
public class JsonResponseDescriptor extends AbstractMessage {

  { //Set parameter requirements for message.
    paramVerDefs.put("subject", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("aliases", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("properties", ParameterVerification.SINGLE_OPTIONAL_MAP.getValue());
    paramVerDefs.put("links", new ParameterVerificationDefinition(new LinksClaimValidator(), true));
  }
  
  public JsonResponseDescriptor() {
    this(new HashMap<String, Object>());
  }

  public JsonResponseDescriptor(Map<String, Object> claims) {
    super(claims);
  }
}
