package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;

public class ArrayClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof String) {
      return value;
    }
    if (!(value instanceof String[]) || ((String[]) value).length == 0) {
      throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
    }
    String spaceSeparatedString = "";
    for (String item : (String[]) value) {
      spaceSeparatedString += spaceSeparatedString.length() > 0 ? " " + item : item;
    }
    return spaceSeparatedString;
  }
}