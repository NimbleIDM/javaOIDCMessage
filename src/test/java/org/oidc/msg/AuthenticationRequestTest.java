package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class AuthenticationRequestTest {

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("response_type", "code");
    claims.put("client_id", "value");
    claims.put("redirect_uri", "value");
    claims.put("scope", "openid");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    Assert.assertEquals("code", req.getClaims().get("response_type"));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
    Assert.assertEquals("value", req.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid",req.getClaims().get("scope"));
  }

  
  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("client_id", "value");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    Assert.assertEquals("value", req.getClaims().get("client_id"));
  }

}