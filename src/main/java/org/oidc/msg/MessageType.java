package org.oidc.msg;

/**
 * Different types of request/response
 */
public enum MessageType {
  AUTHORIZATION_REQUEST, AUTHORIZATION_RESPONSE, TOKEN_RESPONSE, REFRESH_TOKEN_REQUEST, REFRESH_TOKEN_RESPONSE, USER_INFO, JSON_RESPONSE_DESCRIPTOR, PROVIDER_CONFIGURATION_RESPONSE, REGISTRATION_RESPONSE, REGISTRATION_REQUEST, REFRESH_ACCESS_TOKEN_REQUEST, ACCESS_TOKEN_REQUEST, CC_ACCESS_TOKEN_REQUEST, AS_CONFIGURATION_RESPONSE, ACCESS_TOKEN_RESPONSE, NONE_RESPONSE, RESOURCE_REQUEST, USER_INFO_REQUEST, ADDRESS_CLAIM, OPEN_ID_SCHEMA, ID_TOKEN, MESSAGE_WITH_ID_TOKEN, REFRESH_SESSION_REQUEST, WEBFINGER_REQUEST_MESSAGE;
}