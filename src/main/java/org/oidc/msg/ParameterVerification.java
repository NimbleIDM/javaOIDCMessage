package org.oidc.msg;

/** Enum for expressing parameter verification definitions. */
public enum ParameterVerification {

  /** predefined verification types.*/ 
  SINGLE_REQUIRED_STRING(new ParameterVerificationDefinition(ClaimType.STRING, true)), 
  SINGLE_OPTIONAL_STRING(new ParameterVerificationDefinition(ClaimType.STRING, false)),
  SINGLE_REQUIRED_INT(new ParameterVerificationDefinition(ClaimType.INT, true)),
  SINGLE_OPTIONAL_INT(new ParameterVerificationDefinition(ClaimType.INT, false)),
  SINGLE_REQUIRED_BOOLEAN(new ParameterVerificationDefinition(ClaimType.BOOLEAN, true)), 
  SINGLE_OPTIONAL_BOOLEAN(new ParameterVerificationDefinition(ClaimType.BOOLEAN, false)),
  SINGLE_REQUIRED_DATE(new ParameterVerificationDefinition(ClaimType.DATE, true)), 
  SINGLE_OPTIONAL_DATE(new ParameterVerificationDefinition(ClaimType.DATE, false)),
  REQUIRED_LIST_OF_STRINGS(new ParameterVerificationDefinition(ClaimType.LIST,true)),
  OPTIONAL_LIST_OF_STRINGS(new ParameterVerificationDefinition(ClaimType.LIST,false)),
  REQUIRED_LIST_OF_SP_SEP_STRINGS(new ParameterVerificationDefinition(ClaimType.ARRAY,true)),
  OPTIONAL_LIST_OF_SP_SEP_STRINGS(new ParameterVerificationDefinition(ClaimType.ARRAY,false));
 
  /** Verification definition. */
  private ParameterVerificationDefinition parameterVerificationDefinition;

  /**
   * Constructor.
   * 
   * @param parameterVerificationDefinition
   *          Verification definition.
   */
  private ParameterVerification(ParameterVerificationDefinition parameterVerificationDefinition) {
    this.parameterVerificationDefinition = parameterVerificationDefinition;
  }

  /**
   * Get the verification definition.
   * 
   * @return verification definition
   */
  public ParameterVerificationDefinition getValue() {
    return parameterVerificationDefinition;
  }

}
