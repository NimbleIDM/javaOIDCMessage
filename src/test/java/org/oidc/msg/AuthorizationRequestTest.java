package org.oidc.msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class AuthorizationRequestTest {

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("code");
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    AuthorizationRequest req = new AuthorizationRequest(claims);
    Assert.assertEquals("code", ((List<String>) req.getClaims().get("response_type")).get(0));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testSuccessMandatoryAndAdditionalParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("code");
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    claims.put("additional", "value");
    AuthorizationRequest req = new AuthorizationRequest(claims);
    Assert.assertEquals("code", ((List<String>) req.getClaims().get("response_type")).get(0));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
    Assert.assertEquals("value", req.getClaims().get("additional"));

  }

  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("client_id", "value");
    AuthorizationRequest req = new AuthorizationRequest(claims);
    Assert.assertEquals("value", req.getClaims().get("client_id"));
  }

  @SuppressWarnings("unchecked")
  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingClientIdMandatoryParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    List<String> responseType = new ArrayList<String>();
    responseType.add("code");
    claims.put("response_type", responseType);
    AuthorizationRequest req = new AuthorizationRequest(claims);
    Assert.assertEquals("code", ((List<String>) req.getClaims().get("response_type")).get(0));
  }

}