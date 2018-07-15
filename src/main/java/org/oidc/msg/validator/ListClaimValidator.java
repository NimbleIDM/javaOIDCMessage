package org.oidc.msg.validator;

import java.util.Arrays;
import java.util.List;

import org.oidc.msg.InvalidClaimException;

public class ListClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof List) {
      List<?> list = (List<?>) value;
      if (list.isEmpty() || (list.get(0) instanceof String)) {
        return value;
      }
    }
    if (value instanceof String) {
      return Arrays.asList(value);
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }
}
