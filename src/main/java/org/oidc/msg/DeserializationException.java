package org.oidc.msg;

/**
 * An exception that is thrown when there is an issue with deserialization of the Message type
 */
public class DeserializationException extends Exception {

  public DeserializationException(String message) {
    this(message, null);
  }

  public DeserializationException(String message, Throwable cause) {
    super(message, cause);
  }
}
