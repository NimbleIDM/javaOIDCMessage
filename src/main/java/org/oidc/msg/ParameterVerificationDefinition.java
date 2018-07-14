package org.oidc.msg;

/**
 * Class implementing definition on how request/response parameter existence should be verified.
 */
public class ParameterVerificationDefinition {

  /** Whether the parameter is required or not. */
  private boolean required = true;
  /** Type of the parameter. */
  private ClaimType parameterType;

  /**
   * Constructor.
   * 
   * @param parameterType
   *          type of the parameter
   * @param required
   *          whether the parameter is required or not
   */
  public ParameterVerificationDefinition(ClaimType parameterType, boolean required) {
    this.parameterType = parameterType;
    this.required = required;

  }

  /**
   * Get Whether the parameter is required or not.
   * 
   * @return true if the parameter must exist. false otherwise.
   */
  public boolean isRequired() {
    return required;
  }

  /**
   * Get type of the parameter.
   * 
   * @return type of the parameter.
   */
  public ClaimType getParameterType() {
    return parameterType;
  }

}
