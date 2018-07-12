package org.oidc.msg;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authorization Request message as described in https://tools.ietf.org/html/rfc6749 for
 * Authorization Code Grant https://tools.ietf.org/html/rfc6749#section-4.1 and Implicit Grant
 * https://tools.ietf.org/html/rfc6749#section-4.2.
 */
public class AuthorizationRequest extends AbstractMessage {

  /**
   * Required claims that need to be set.
   */
  protected final List<String> requiredClaims = new ArrayList<String>();

  /**
   * Constructor.
   * 
   * @param claims
   *          Authorization request claims. Expected claims are response_type(REQUIRED),
   *          client_id(REQUIRED), redirect_uri(OPTIONAL), scope (OPTIONAL) and state(RECOMMENDED).
   */
  public AuthorizationRequest(Map<String, Object> claims) {
    super(claims);
    requiredClaims.add("response_type");
    requiredClaims.add("client_id");
  }

  @Override
  protected List<String> getRequiredClaims() {
    return requiredClaims;
  }

  @Override
  public MessageType fetchMessageType() {
    return MessageType.AUTHORIZATION_REQUEST;
  }

  @Override
  public boolean allowCustomClaims() {
    return true;
  }
}