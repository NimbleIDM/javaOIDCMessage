package org.oidc.msg;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ProviderConfigurationResponse extends AbstractMessage {
  
  { //Set parameter requirements for message.
    paramVerDefs.put("issuer", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("authorization_endpoint", 
        ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("token_endpoint", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("userinfo_endpoint", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("jwks_uri", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    paramVerDefs.put("registration_endpoint", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("scopes_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_types_supported", 
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("response_modes_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("grant_types_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("acr_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("subject_types_supported", 
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("id_token_signing_alg_values_supported", 
        ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("id_token_encryption_alg_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("id_token_encryption_enc_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("userinfo_signing_alg_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("userinfo_encryption_alg_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("userinfo_encryption_enc_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("request_object_signing_alg_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("request_object_encryption_alg_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("request_object_encryption_enc_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("token_endpoint_auth_methods_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("token_endpoint_auth_signing_alg_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("display_values_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("claim_types_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("claims_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("service_documentation", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("claims_locales_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("ui_locales_supported", 
        ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    paramVerDefs.put("claims_parameter_supported", 
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("request_parameter_supported", 
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("request_uri_parameter_supported", 
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("require_request_uri_registration", 
        ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    paramVerDefs.put("op_policy_uri", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("op_tos_uri", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("check_session_iframe", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    paramVerDefs.put("end_session_endpoint", 
        ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    
    defaultValues.put("version", "3.0");
    defaultValues.put("token_endpoint_auth_methods_supported", 
        Arrays.asList("client_secret_basic"));
    defaultValues.put("claims_parameter_supported", Boolean.FALSE);
    defaultValues.put("request_parameter_supported", Boolean.FALSE);
    defaultValues.put("request_uri_parameter_supported", Boolean.TRUE);
    defaultValues.put("require_request_uri_registration", Boolean.TRUE);
    defaultValues.put("grant_types_supported", 
        Arrays.asList("authorization_code", "implicit"));
  }

  public ProviderConfigurationResponse() {
    this(new HashMap<String, Object>());
  }

  public ProviderConfigurationResponse(Map<String, Object> claims) {
    super(claims);
    addDefaultValues();
  }
}