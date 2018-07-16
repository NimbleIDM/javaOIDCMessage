package org.oidc.msg.validator;

import java.util.Map;

import org.oidc.msg.InvalidClaimException;

public class MapClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof Map) {
      Map<?, ?> map = (Map<?, ?>) value;
      if (map.isEmpty()) {
        return value;
      }
      Object key = map.keySet().iterator().next();
      if (!(key instanceof String)) {
        throw new InvalidClaimException("Unexpected key type in the map: " + key.getClass());
      }
      return map;
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }
}
