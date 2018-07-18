package org.oidc.msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.oidc.msg.oidc.OpenIDSchema;

public class OpenIDSchemaTest {

  Map<String, Object> claims = new HashMap<String, Object>();

  /**
   * Setuo mandatory claims.
   */
  @Before
  public void setup() {
    claims.clear();
    claims.put("sub", "foo");
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    OpenIDSchema req = new OpenIDSchema(claims);
    req.verify();
    Assert.assertEquals("foo", req.getClaims().get("sub"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailMissingOpenidScopeParameter() throws InvalidClaimException {
    claims.remove("sub");
    OpenIDSchema req = new OpenIDSchema(claims);
    req.verify();
  }
  
  @Test
  public void testSuccessDateFormats() throws InvalidClaimException {
    OpenIDSchema req = new OpenIDSchema(claims);
    claims.put("birthdate", "1990-12-31");
    req.verify();
    claims.put("birthdate", "0000-12-31");
    req.verify();
    claims.put("birthdate", "1990");
    req.verify();
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testFailDateFormats() throws InvalidClaimException {
    OpenIDSchema req = new OpenIDSchema(claims);
    claims.put("birthdate", "X-1555-15");
    req.verify();
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testFailNullValue() throws InvalidClaimException {
    OpenIDSchema req = new OpenIDSchema(claims);
    claims.put("any", null);
    req.verify();
  }
  
}