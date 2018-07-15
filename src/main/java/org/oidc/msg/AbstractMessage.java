package org.oidc.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

/**
 * This abstract class provides basic processing of messages.
 */
public abstract class AbstractMessage implements Message {
  /** Message request/response parameters. */
  private Map<String, Object> claims;
  /** Header when message is jwt like signed userinfo response. */
  private Map<String, Object> header;
  /** Error if such has happened during message verification. */
  private Error error = new Error();
  /** Json (de)serialization. */
  private ObjectMapper mapper = new ObjectMapper();
  /** Whether the message has been verified. */
  private boolean verified;

  /**
   * Constructor.
   */
  protected AbstractMessage() {
    this(Collections.<String, Object>emptyMap());
  }

  /**
   * Constructor.
   * 
   * @param claims
   *          message parameters
   */
  protected AbstractMessage(Map<String, Object> claims) {
    this.claims = claims;
  }

  /**
   * Constructs message from urlEncoded String representation of a message.
   * 
   * @param input
   *          the urlEncoded String representation of a message
   */
  public void fromUrlEncoded(String input) throws MalformedURLException, IOException {
    String msgJson = StringUtils.newStringUtf8(Base64.decodeBase64(input));
    Map<String, Object> newClaims = mapper.readValue(msgJson,
        new TypeReference<Map<String, Object>>() {
        });
    this.claims = newClaims;
    verified = false;
  }

  /**
   * Takes the claims of this instance of the AbstractMessage class and serializes them to an
   * urlEncoded string.
   *
   * @return an urlEncoded string
   * @throws InvalidClaimException
   *           if the message is invalid
   */
  public String toUrlEncoded()
      throws SerializationException, JsonProcessingException, InvalidClaimException {
    if (!verified) {
      verify();
    }
    String jsonMsg = mapper.writeValueAsString(this.claims);
    String urlEncodedMsg = Base64
        .encodeBase64URLSafeString(jsonMsg.getBytes(StandardCharsets.UTF_8));
    return urlEncodedMsg;
  }

  /**
   * Constructs message from JSON string values.
   * 
   * @param input
   *          The JSON String representation of a message
   */
  public void fromJson(String input) throws InvalidClaimException {
    Map<String, Object> newClaims;
    try {
      newClaims = mapper.readValue(input, new TypeReference<Map<String, Object>>() {
      });
    } catch (IOException e) {
      throw new InvalidClaimException(String.format("Unable to parse message from '%s'", input));
    }
    this.claims = newClaims;
    verified = false;
  }

  /**
   * Takes the parameters of this instance of the AbstractMessage class and serializes them to a
   * json string.
   *
   * @return a JSON String representation in the form of a hashMap mapping string -> string
   * @throws InvalidClaimException
   *           thrown if message parameters do not match the message requirements.
   */
  public String toJson() throws JsonProcessingException, InvalidClaimException {
    if (!verified) {
      verify();
    }
    String jsonMsg = mapper.writeValueAsString(claims);
    return jsonMsg;
  }

  /**
   * Constructs message from JWT.
   * 
   * @param input
   *          the jwt String representation of a message
   * @throws InvalidClaimException
   *           thrown if message parameters do not match the message requirements.
   */
  @SuppressWarnings("unchecked")
  public void fromJwt(String input) throws IOException {
    String[] parts = MessageUtil.splitToken(input);
    String headerJson;
    String payloadJson;
    try {
      headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
      payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
    } catch (NullPointerException e) {
      throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
    }
    this.header = mapper.readValue(headerJson, Map.class);
    this.claims = mapper.readValue(payloadJson, Map.class);
    verified = false;
  }

  /**
   * Serialize the content of this instance (the claims map) into a jwt string.
   * 
   * @param algorithm
   *          the algorithm to use in signing the JWT
   * @return a jwt String
   * @throws InvalidClaimException
   *           thrown if message parameters do not match the message requirements.
   */
  public String toJwt(Algorithm algorithm)
      throws JsonProcessingException, SerializationException, InvalidClaimException {
    if (!verified) {
      verify();
    }
    header.put("alg", algorithm.getName());
    header.put("typ", "JWT");
    String signingKeyId = algorithm.getSigningKeyId();
    if (signingKeyId != null) {
      header.put("kid", signingKeyId);
    }
    JWTCreator.Builder newBuilder = JWT.create().withHeader(this.header);
    for (String claimName : claims.keySet()) {
      // TODO this needs to be extended for all claim types
      Object value = claims.get(claimName);
      if (value instanceof Boolean) {
        newBuilder.withClaim(claimName, (Boolean) value);
      } else if (value instanceof String) {
        newBuilder.withClaim(claimName, (String) value);
      } else if (value instanceof Date) {
        newBuilder.withClaim(claimName, (Date) value);
      } else if (value instanceof Long) {
        newBuilder.withClaim(claimName, (Long) value);
      }
    }
    return newBuilder.sign(algorithm);
  }

  /**
   * Verifies the presence of required message parameters. Verifies the the format of message
   * parameters.
   * 
   * @return true if parameters are successfully verified.
   * @throws InvalidClaimException
   *           if verification fails.
   */
  @SuppressWarnings("rawtypes")
  protected boolean verify() throws InvalidClaimException {
    error.getMessages().clear();
    Map<String, ParameterVerificationDefinition> paramVerDefs = 
        getParameterVerificationDefinitions();
    if (paramVerDefs == null || paramVerDefs.isEmpty()) {
      verified = true;
      return true;
    }
    for (String paramName : paramVerDefs.keySet()) {
      // If parameter is defined as REQUIRED, it must exist.
      if (paramVerDefs.get(paramName).isRequired()
          && (!claims.containsKey(paramName) || claims.get(paramName) == null)) {
        error.getMessages().add(String.format("Required parameter '%s' is missing", paramName));
      }
      Object value = claims.get(paramName);
      if (value == null) {
        continue;
      }
      // If parameter exists, we verify the type of it and possibly transform it.
      switch (paramVerDefs.get(paramName).getParameterType()) {
        case BOOLEAN:
          if (!(value instanceof Boolean)) {
            error.getMessages()
                .add(String.format("Parameter '%s' is not of expected type", paramName));
          }
          break;
  
        case STRING:
          if (!(value instanceof String)) {
            error.getMessages()
                .add(String.format("Parameter '%s' is not of expected type", paramName));
          }
          break;
  
        case INT:
          if (value instanceof Long) {
            break;
          } // convert Integer to Long.
          if (value instanceof Integer) {
            claims.put(paramName, ((Integer) value).longValue());
            break;
          } // convert String to Long if possible and update the value.
          if (value instanceof String) {
            try {
              long longValue = Long.parseLong((String) value);
              claims.put(paramName, longValue);
              break;
            } catch (NumberFormatException e) {
              // We mark the error in the end of case.
            }
          }
          error.getMessages().add(String.format("Parameter '%s' is not of expected type", paramName));
          break;
  
        case DATE:
          if (value instanceof Date) {
            break;
          } // Convert Integer and Long to Date if possible.
          if (value instanceof Integer || value instanceof Long) {
            long epoch;
            if (value instanceof Integer) {
              epoch = ((Integer) value).longValue();
            } else {
              epoch = (Long) value;
            }
            claims.put(paramName, new Date(epoch));
            break;
          }
          error.getMessages().add(String.format("Parameter '%s' is not of expected type", paramName));
          break;
  
        case LIST:
          if ((value instanceof List) && (((List) value).get(0) instanceof String)) {
            break;
          } // If there is String we set it to list
          if (value instanceof String) {
            List<String> listParam = new ArrayList<String>();
            listParam.add((String) value);
            claims.put(paramName, listParam);
            break;
          }
          error.getMessages().add(String.format("Parameter '%s' is not of expected type", paramName));
          break;
  
        case ARRAY:
          if (value instanceof String) {
            break;
          }
          if (!(value instanceof String[]) || ((String[]) value).length == 0) {
            error.getMessages().add(
                String.format("The claim '%s' type is not appropriate for this claim'", paramName));
            break;
          }
          String spaceSeparatedString = "";
          for (String item : (String[]) value) {
            spaceSeparatedString += spaceSeparatedString.length() > 0 ? " " + item : item;
          }
          claims.put(paramName, spaceSeparatedString);
          break;
  
        case ID_TOKEN:
          if (!(value instanceof IDToken)) {
            error.getMessages().add(
                String.format("The claim '%s' type is not appropriate for this claim'", paramName));
            break;
          }
          verified = ((IDToken) value).verify();
          return ((IDToken) value).verify();
  
        default:
          break;
      }

    }
    if (error.getMessages().size() > 0) {
      throw new InvalidClaimException(
          "Message parameter verification failed. See Error object for details");
    }
    verified = true;
    return true;
  }

  /**
   * Get error description of message parameter verification.
   * @return Error an object representing the error status of message parameter verification.
   */
  public Error getError() {
    return error;
  }

  /**
   * Get the message parameters.
   * 
   * @return List of the list of claims for this message
   */
  public Map<String, Object> getClaims() throws InvalidClaimException {
    if (!verified) {
      verify();
    }
    return this.claims;
  }

  /**
   * add the claim to this instance of message.
   * 
   * @param name
   *          the name of the claim
   * @param value
   *          the value of the claim to add to this instance of Message
   */
  public void addClaim(String name, Object value) {
    this.claims.put(name, value);
    verified = false;
  }

  /**
   * Get parameter verification definitions.
   * 
   * @return parameter verification definitions
   */
  abstract Map<String, ParameterVerificationDefinition> getParameterVerificationDefinitions();

  /**
   * Whether there is an error in verification.
   * 
   * @return boolean for whether there is an error in verification.
   */
  public boolean hasError() {
    return error.getMessages() != null;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toString() {
    // Override to return user friendly value
    return super.toString();
  }
}