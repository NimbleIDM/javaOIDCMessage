package org.oidc.msg;

import java.util.ArrayList;
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
  
  @Test
  public void testSuccessResponseTypeIdToken() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    claims.put("nonce", "DFHGFG");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals("DFHGFG", (String) req.getClaims().get("nonce"));
    Assert.assertEquals("id_token token", req.getClaims().get("response_type"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testFailResponseTypeIdTokenMissingNonce() throws InvalidClaimException {
    claims.put("response_type", "id_token token");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
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

  @Test(expected = InvalidClaimException.class)
  public void testFailInvalidPromptCombination() throws InvalidClaimException {
    List<String> prompt = new ArrayList<String>();
    prompt.add("none");
    prompt.add("consent");
    claims.put("prompt", prompt);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailUnAllowedPromptValue() throws InvalidClaimException {
    claims.put("prompt", "notlisted");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

  @Test(expected = InvalidClaimException.class)
  public void testFailUnAllowedDisplayValue() throws InvalidClaimException {
    claims.put("display", "notlisted");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
  }

}