package org.oidc.msg;

import org.oidc.msg.validator.ArrayClaimValidator;
import org.oidc.msg.validator.BooleanClaimValidator;
import org.oidc.msg.validator.DateClaimValidator;
import org.oidc.msg.validator.IntClaimValidator;
import org.oidc.msg.validator.ListClaimValidator;
import org.oidc.msg.validator.MapClaimValidator;
import org.oidc.msg.validator.StringClaimValidator;
import org.oidc.msg.validator.MessageClaimValidator;

/** Enum for expressing parameter verification definitions. */
public enum ParameterVerification {

  /** predefined verification types.*/ 
  SINGLE_REQUIRED_STRING(new ParameterVerificationDefinition(new StringClaimValidator(), true)), 
  SINGLE_OPTIONAL_STRING(new ParameterVerificationDefinition(new StringClaimValidator(), false)),
  SINGLE_REQUIRED_INT(new ParameterVerificationDefinition(new IntClaimValidator(), true)),
  SINGLE_OPTIONAL_INT(new ParameterVerificationDefinition(new IntClaimValidator(), false)),
  SINGLE_REQUIRED_BOOLEAN(new ParameterVerificationDefinition(new BooleanClaimValidator(), true)), 
  SINGLE_OPTIONAL_BOOLEAN(new ParameterVerificationDefinition(new BooleanClaimValidator(), false)),
  SINGLE_REQUIRED_DATE(new ParameterVerificationDefinition(new DateClaimValidator(), true)), 
  SINGLE_OPTIONAL_DATE(new ParameterVerificationDefinition(new DateClaimValidator(), false)),
  SINGLE_REQUIRED_MAP(new ParameterVerificationDefinition(new MapClaimValidator(), true)),
  SINGLE_OPTIONAL_MAP(new ParameterVerificationDefinition(new MapClaimValidator(), false)),
  REQUIRED_LIST_OF_STRINGS(new ParameterVerificationDefinition(new ListClaimValidator(), true)),
  OPTIONAL_LIST_OF_STRINGS(new ParameterVerificationDefinition(new ListClaimValidator(),false)),
  REQUIRED_LIST_OF_SP_SEP_STRINGS(new ParameterVerificationDefinition(new ArrayClaimValidator(), true)),
  OPTIONAL_LIST_OF_SP_SEP_STRINGS(new ParameterVerificationDefinition(
      new ArrayClaimValidator(), false)),
  SINGLE_REQUIRED_MESSAGE(new ParameterVerificationDefinition(new MessageClaimValidator(), true)), 
  SINGLE_OPTIONAL_MESSAGE(new ParameterVerificationDefinition(new MessageClaimValidator(), false));
  
 
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
