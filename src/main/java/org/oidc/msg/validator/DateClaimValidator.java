package org.oidc.msg.validator;

import java.util.Date;

import org.oidc.msg.InvalidClaimException;

public class DateClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof Date) {
      return value;
    } // Convert Integer and Long to Date if possible.
    if (value instanceof Integer) {
      return new Date(((Integer) value).longValue());
    }
    if (value instanceof Long) {
      return new Date((Long) value);
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}
