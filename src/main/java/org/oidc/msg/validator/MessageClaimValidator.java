package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;

/** General validator for claims type of message. */
public class MessageClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (!(value instanceof Message)) {
      throw new InvalidClaimException(
          String.format("Parameter '%s' is not of expected type", value));
    }
    // TODO: the reason for failing the verification is not carried to calling layers
    if (!((Message) value).verify()) {
      throw new InvalidClaimException(String.format("Parameter '%s' verification failed", value));
    }
    return value;
  }
}
