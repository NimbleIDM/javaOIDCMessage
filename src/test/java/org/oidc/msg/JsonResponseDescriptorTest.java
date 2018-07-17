package org.oidc.msg;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;

/**
 * Unit tests for {@link JsonResponseDescriptor}.
 */
public class JsonResponseDescriptorTest {
  
  @Test
  public void testFromJson() throws InvalidClaimException, JsonProcessingException {
    String json = "{ \"subject\" : \"acct:juliet%40capulet.example@shopping.example.com\",\n" + 
        "   \"links\":\n" + 
        "    [\n" + 
        "     {\n" + 
        "      \"rel\": \"http://openid.net/specs/connect/1.0/issuer\",\n" + 
        "      \"href\": \"https://server.example.com\"\n" + 
        "     }\n" + 
        "    ]\n" + 
        "  }";
    JsonResponseDescriptor jrd = new JsonResponseDescriptor();
    jrd.fromJson(json);
    jrd.verify();
    Map<String, Object> claims = jrd.getClaims();
    Assert.assertEquals("acct:juliet%40capulet.example@shopping.example.com", claims.get("subject"));
    List<Link> links = (List<Link>) claims.get("links");
    Assert.assertNotNull(links);
    Assert.assertEquals(links.size(), 1);
    Map<String, Object> linkClaims = links.get(0).getClaims();
    Assert.assertEquals("http://openid.net/specs/connect/1.0/issuer", linkClaims.get("rel"));
    Assert.assertEquals("https://server.example.com", linkClaims.get("href"));
  }
  
  @Test
  public void testFromClaims() throws JsonProcessingException, InvalidClaimException {
    Map<String, Object> claims = new HashMap<String, Object>();
    claims.put("subject", "acct:juliet%40capulet.example@shopping.example.com");
    List<Link> links = new ArrayList<Link>();
    Link link = new Link();
    link.addClaim("rel", "http://openid.net/specs/connect/1.0/issuer");
    link.addClaim("href", "https://server.example.com");
    links.add(link);
    claims.put("links", links);
    JsonResponseDescriptor jrd = new JsonResponseDescriptor(claims);
    jrd.verify();
    Map<String, Object> parsedClaims = jrd.getClaims();
    Assert.assertEquals("acct:juliet%40capulet.example@shopping.example.com", parsedClaims.get("subject"));
    List<Link> parsedLinks = (List<Link>) parsedClaims.get("links");
    Assert.assertNotNull(parsedLinks);
    Assert.assertEquals(parsedLinks.size(), 1);
    Map<String, Object> linkClaims = parsedLinks.get(0).getClaims();
    Assert.assertEquals("http://openid.net/specs/connect/1.0/issuer", linkClaims.get("rel"));
    Assert.assertEquals("https://server.example.com", linkClaims.get("href"));
  }

}
