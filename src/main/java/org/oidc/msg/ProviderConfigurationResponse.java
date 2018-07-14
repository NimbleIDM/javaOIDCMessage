package org.oidc.msg;

import java.util.List;
import java.util.Map;

public class ProviderConfigurationResponse extends AbstractMessage {

  public ProviderConfigurationResponse() {
  }

  public ProviderConfigurationResponse(Map<String, Object> claims) {
    super(claims);
  }

  /*
  @Override
  protected List<String> getRequiredClaims() {
    return null;
  }
  */

  @Override
  public Map<String, Object> getClaims() throws InvalidClaimException {
    return super.getClaims();
  }

  /*
  @Override
  public MessageType fetchMessageType() {
    return MessageType.PROVIDER_CONFIGURATION_RESPONSE;
  }
  */

  @Override
  public boolean allowCustomClaims() {
    return true;
  }

  @Override
  Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions() {
    // TODO Auto-generated method stub
    return null;
  }
}