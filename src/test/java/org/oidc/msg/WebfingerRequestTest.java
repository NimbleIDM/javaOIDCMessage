package org.oidc.msg;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit tests for {@link WebfingerRequest}.
 */
public class WebfingerRequestTest {
  
  @Test
  public void testDefaultRelParameter() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("resource", "value");
    WebfingerRequest req = new WebfingerRequest();
    req.addClaim("resource", "value");
    req.verify();
    Map<String, Object> msgClaims = req.getClaims();
    Assert.assertEquals("value", msgClaims.get("resource"));
    Assert.assertEquals("http://openid.net/specs/connect/1.0/issuer", msgClaims.get("rel"));
  }

  @Test
  public void testSuccessMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("resource", "value");
    claims.put("rel", "relValue");
    WebfingerRequest req = new WebfingerRequest(claims);
    req.verify();
    Map<String, Object> msgClaims = req.getClaims();
    Assert.assertEquals("value", msgClaims.get("resource"));
    Assert.assertEquals("relValue", msgClaims.get("rel"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testFailureMissingResponseTypeMandatoryParameters() throws InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("custom", "value");
    WebfingerRequest req = new WebfingerRequest(claims);
    req.verify();
  }

}
