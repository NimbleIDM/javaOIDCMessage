package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;

public class IntClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof Long) {
      return value;
    } // convert Integer to Long.
    if (value instanceof Integer) {
      return ((Integer) value).longValue();
    } // convert String to Long if possible and update the value.
    if (value instanceof String) {
      try {
        return Long.parseLong((String) value);
      } catch (NumberFormatException e) {
        // We mark the error in the end of case.
      }
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}
