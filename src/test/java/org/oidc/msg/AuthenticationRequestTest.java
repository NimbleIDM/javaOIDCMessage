package org.oidc.msg;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationRequestTest {

  Map<String, Object> claims = new HashMap<String, Object>();

  /**
   * Setuo mandatory claims.
   */
  @Before
  public void setup() {
    claims.clear();
    claims.put("response_type", "code");
    claims.put("client_id", "value");
    claims.put("redirect_uri", "value");
    claims.put("scope", "openid");
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals("code", req.getClaims().get("response_type"));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
    Assert.assertEquals("value", req.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid", req.getClaims().get("scope"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailMissingOpenidScopeParameter() throws InvalidClaimException {
    claims.put("scope", "profile");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessOfflineAccess() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    claims.put("prompt", "consent");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals("consent", ((List<String>) req.getClaims().get("prompt")).get(0));
    Assert.assertEquals("openid offline_access", req.getClaims().get("scope"));
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailOfflineAccessNoConsent() throws InvalidClaimException {
    claims.put("scope", "openid offline_access");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.remove("client_id");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

}