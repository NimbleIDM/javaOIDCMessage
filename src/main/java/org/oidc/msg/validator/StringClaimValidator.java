package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;

public class StringClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (!(value instanceof String)) {
      throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
    }
    return value;
  }
}
