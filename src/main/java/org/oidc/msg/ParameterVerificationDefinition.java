package org.oidc.msg;

import org.oidc.msg.validator.ClaimValidator;

/**
 * Class implementing definition on how request/response parameter existence should be verified.
 */
public class ParameterVerificationDefinition {

  /** Whether the parameter is required or not. */
  private boolean required = true;
  /** Claim validator used to validate the structure of the parameter value. */
  private ClaimValidator claimValidator;

  /**
   * Constructor.
   * 
   * @param validator
   *          claim validator used to validate the structure of the parameter value
   * @param required
   *          whether the parameter is required or not
   */
  public ParameterVerificationDefinition(ClaimValidator validator, boolean required) {
    this.claimValidator = validator;
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
   * Get the claim validator used to validate the structure of the parameter value.
   * 
   * @return Claim validator used to validate the structure of the parameter value
   */
  public ClaimValidator getClaimValidator() {
    return claimValidator;
  }
  
}
