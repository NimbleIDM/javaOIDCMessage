package org.oidc.msg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class AuthorizationRequestTest {

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {

    Map<String, Object> claims = new HashMap<String, Object>();
    String[] responseType = new String[2];
    responseType[0] = "id_token";
    responseType[1] = "token";
    claims.put("response_type", responseType);
    claims.put("client_id", "value");
    AuthorizationRequest req = new AuthorizationRequest(claims);
    Assert.assertEquals("id_token token", req.getClaims().get("response_type"));
    Assert.assertEquals("value", req.getClaims().get("client_id"));
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