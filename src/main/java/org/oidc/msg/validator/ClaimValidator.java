package org.oidc.msg.validator;

import org.oidc.msg.InvalidClaimException;

public interface ClaimValidator {
  
  public Object validate(Object value) throws InvalidClaimException;

}
