package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;

public class BooleanClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (!(value instanceof Boolean)) {
      throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
    }
    return value;
  }

}
