package org.oidc.msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class AuthenticationRequestTest {

  @SuppressWarnings("unchecked")
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

  @SuppressWarnings("unchecked")
  //@Test(expected = InvalidClaimException.class)
  public void testFailureMissingNonce() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("id_token");
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    claims.put("redirect_uri", "value");
    List<String> scope = new ArrayList<String>();
    scope.add("openid");
    claims.put("scope", scope);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    Assert.assertEquals("id_token", ((List<String>) req.getClaims().get("response_type")).get(0));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
    Assert.assertEquals("value", req.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid", ((List<String>) req.getClaims().get("scope")).get(0));
  }

  @SuppressWarnings("unchecked")
  //@Test
  public void testSuccessMandatoryAndAdditionalParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("code");
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    claims.put("redirect_uri", "value");
    List<String> scope = new ArrayList<String>();
    scope.add("openid");
    claims.put("scope", scope);
    claims.put("additional", "value");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    Assert.assertEquals("code", ((List<String>) req.getClaims().get("response_type")).get(0));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
    Assert.assertEquals("value", req.getClaims().get("redirect_uri"));
    Assert.assertEquals("openid", ((List<String>) req.getClaims().get("scope")).get(0));
    Assert.assertEquals("value", req.getClaims().get("additional"));
  }

  //@Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("client_id", "value");
    AuthenticationRequest req = new AuthenticationRequest(claims);
    Assert.assertEquals("value", req.getClaims().get("client_id"));
  }

}