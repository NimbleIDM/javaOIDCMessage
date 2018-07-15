package org.oidc.msg;

import java.util.Map;

public class ProviderConfigurationResponse extends AbstractMessage {

  public ProviderConfigurationResponse() {
  }

  public ProviderConfigurationResponse(Map<String, Object> claims) {
    super(claims);
  }

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return super.getClaims();
  }
}