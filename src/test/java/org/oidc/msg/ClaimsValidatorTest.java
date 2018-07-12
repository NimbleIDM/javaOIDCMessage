package org.oidc.msg;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ClaimsValidatorTest {
  @Rule
  public ExpectedException exception = ExpectedException.none();

  @Before
  public void setUp() throws Exception {

  }

  @Test
  public void testValidateAllowedValuePass() throws InvalidClaimException {
    ClaimsValidator.validate("grant_type", "refresh_token",
        MessageType.REFRESH_ACCESS_TOKEN_REQUEST);
  }

  @Test
  public void testValidateNoAllowedValuePass() throws InvalidClaimException {
    ClaimsValidator.validate("grant_type", "bad_value!", MessageType.ACCESS_TOKEN_REQUEST);
  }

  @Test
  public void testValidateRequiredValueFail() throws Exception {
    exception.expect(InvalidClaimException.class);
    exception.expectMessage(
        String.format("The claim '%s' value is not allowed for this claim type", "grant_type"));

    ClaimsValidator.validate("grant_type", "refresh_token!",
        MessageType.REFRESH_ACCESS_TOKEN_REQUEST);
  }
}
