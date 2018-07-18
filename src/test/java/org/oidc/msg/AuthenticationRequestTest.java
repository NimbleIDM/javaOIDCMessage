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
   * Setup mandatory claims.
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

  @Test
  public void testSuccessIdTokenHint() throws InvalidClaimException {
    // TODO: There is no capability in is token to verify signature nor timestamps or sorts yet.
    // Once there is, this test will fail and needs to be updated to produce id token that passes
    // validation.
    String idToken = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlz"
        + "cyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4"
        + "Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAi"
        + "bi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEz"
        + "MTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6"
        + "ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJm"
        + "ZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6"
        + "ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9l"
        + "eGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNn"
        + "spA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcip"
        + "R2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2mac"
        + "AAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOY"
        + "u0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD"
        + "4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl" 
        + "6cQQWNiDpWOl_lxXjQEvQ";
    claims.put("id_token_hint", idToken);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals(idToken, req.getClaims().get("id_token_hint"));
  }

  @Test(expected = Exception.class)
  public void testFailIdTokenHintInvalid() throws InvalidClaimException {
    String idToken = "notparsableasidtoken";
    claims.put("id_token_hint", idToken);
    AuthenticationRequest req = new AuthenticationRequest(claims);
    req.verify();
    Assert.assertEquals(idToken, req.getClaims().get("id_token_hint"));
  }

}