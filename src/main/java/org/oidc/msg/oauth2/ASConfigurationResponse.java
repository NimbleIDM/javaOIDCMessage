package org.oidc.msg.oauth2;

import java.util.HashMap;
import java.util.Map;

import org.oidc.msg.ParameterVerification;

/**
 * OAuth2 Authorization Server configuration response.
 */
public class ASConfigurationResponse extends ResponseMessage {

  { // Set parameter requirements for message.
    paramVerDefs.put("issuer", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("authorization_endpoint",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("token_endpoint", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("jwks_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("registration_endpoint",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("scopes_supported", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_types_supported",
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_modes_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("grant_types_supported",
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("token_endpoint_auth_methods_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("token_endpoint_auth_signing_alg_values_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("service_documentation",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("ui_locales_supported",
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("op_policy_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("op_tos_uri", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("revocation_endpoint",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("introspection_endpoint",
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());

    defaultValues.put("version", "3.0");
  }

  public ASConfigurationResponse() {
    this(new HashMap<String, Object>());
  }

  public ASConfigurationResponse(Map<String, Object> claims) {
    super(claims);
    addDefaultValues();
  }
}
