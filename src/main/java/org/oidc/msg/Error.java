package org.oidc.msg;

import java.util.ArrayList;
import java.util.List;

/** Error class for message verification failures. */
public class Error {
  private List<String> messages = new ArrayList<String>();

  /**
   * Constructor.
   */
  public Error() {
  }

  /**
   * Get Message verification failure messages.
   * 
   * @return message verification failure messages
   */
  public List<String> getMessages() {
    return this.messages;
  }
}