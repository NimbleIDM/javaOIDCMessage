package org.oidc.msg;

import com.auth0.jwt.impl.PayloadSerializer;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.junit.Before;
import org.junit.Test;

import org.junit.Assert;

import java.io.StringWriter;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;

public class AbstractMessageTest {
  private StringWriter writer;
  private PayloadSerializer serializer;
  private JsonGenerator jsonGenerator;
  private SerializerProvider serializerProvider;

  
  //TODO: Old tests start here. go through them and make sense out of them.
  
  @Before
  public void setUp() throws Exception {
    writer = new StringWriter();
    serializer = new PayloadSerializer();
    jsonGenerator = new JsonFactory().createGenerator(writer);
    ObjectMapper mapper = new ObjectMapper();
    jsonGenerator.setCodec(mapper);
    serializerProvider = mapper.getSerializerProvider();
  }

  @Test
  public void testToUrlEncoded() throws Exception {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("GRANT_TYPE", "refresh_token");

    MockMessage pcr = new MockMessage(claims);
    String pcrUrlEncoded = pcr.toUrlEncoded();
  }

  @Test
  public void testToJson() throws Exception {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("GRANT_TYPE", "refresh_token");

    MockMessage pcr = new MockMessage(claims);
    String pcrJson = pcr.toJson();
    String testJson = "{\"GRANT_TYPE\":\"refresh_token\"}";
    Assert.assertThat(pcrJson, is(testJson));
  }

  @Test
  public void testFromJson() throws Exception {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("GRANT_TYPE", "refresh_token");
    String testJson = "{\"GRANT_TYPE\":\"refresh_token\"}";
    MockMessage pcr = new MockMessage(claims);
    pcr.fromJson(testJson);
    Map<String, Object> claims2 = pcr.getClaims();

    Assert.assertEquals(pcr.getClaims(), claims);
  }

  // New tests ->
  
  @Test(expected = InvalidClaimException.class)
  public void failureMissingRequiredParam() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter2", ParameterVerification.SINGLE_REQUIRED_STRING.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),"value");
  }

  @Test
  public void successMissingOptionalParams() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter2", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    parVerDef.put("parameter3", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    parVerDef.put("parameter4", ParameterVerification.OPTIONAL_LIST_OF_SP_SEP_STRINGS.getValue());
    parVerDef.put("parameter5", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),"value");
  }
  
  @Test
  public void successTestStringType() throws InvalidClaimException, 
                        JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),"value");
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":\"value\"}");
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failTestStringType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", 1);
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.triggerVerify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),1);
  }
  
  @Test
  public void successTestIntType() throws InvalidClaimException, 
                  JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", new Long(5));
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), 5L);
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":5}");
  }
  
  @Test
  public void successIntTypeConversion()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", new Integer(5));
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), 5L);
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":5}");
  }

  @Test
  public void successIntTypeConversion2()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "57");
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), 57L);
    Assert.assertEquals(mockMessage.toJson(), "{\"parameter1\":57}");
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failTestIntType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "fail");
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_INT.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),"fail");
  }
  
  @SuppressWarnings("unchecked")
  @Test
  public void successTestListType()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    values.add("value2");
    claims.put("parameter1", values);
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0), "value");
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(1),
        "value2");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"value\",\"value2\"]}"));
  }
  
  @SuppressWarnings("unchecked")
  @Test
  public void successTestListTypeAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    values.add("value2");
    claims.put("parameter1", values);
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("value", "value2", "evenMore"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0), "value");
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(1),
        "value2");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"value\",\"value2\"]}"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failedTestListTypeNotAllAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    values.add("value2");
    claims.put("parameter1", values);
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("value", "evenMore"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    mockMessage.triggerVerify();
  }
  
  @SuppressWarnings("unchecked")
  @Test
  public void successTestListTypeConversion()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "values");
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0),
        "values");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"values\"]}"));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void successTestListTypeConversionAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "values");
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("values"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0),
        "values");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":[\"values\"]}"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failedTestListTypeConversionNotAllowed()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "values");
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    Map<String, List<?>> allowedValues = new HashMap<String, List<?>>();
    allowedValues.put("parameter1", Arrays.asList("notValues"));
    MockMessage mockMessage = new MockMessage(claims, parVerDef, allowedValues);
    mockMessage.triggerVerify();
  }
  
  @SuppressWarnings("unchecked")
  @Test(expected = InvalidClaimException.class)
  public void failTestListType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    List<String> values = new ArrayList<String>();
    values.add("value");
    claims.put("parameter1", 1);
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.OPTIONAL_LIST_OF_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(((List<String>) mockMessage.getClaims().get("parameter1")).get(0),"values");
  }
  
  @Test
  public void successTestArrayType()
      throws InvalidClaimException, JsonProcessingException, SerializationException {
    HashMap<String, Object> claims = new HashMap<>();
    String[] strArr = (String[]) Array.newInstance(String.class, 2);
    strArr[0] = "value";
    strArr[1] = "value2";
    claims.put("parameter1", strArr);
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"), "value value2");
    Assert.assertThat(mockMessage.toJson(), is("{\"parameter1\":\"value value2\"}"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failTestArrayType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", 1);
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.REQUIRED_LIST_OF_SP_SEP_STRINGS.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(((String[])mockMessage.getClaims().get("parameter1"))[0],"value");
  }
  
  @Test
  public void successTestBooleanType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", true);
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),true);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failTestBooleanType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_BOOLEAN.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),"value");
  }
  
  @Test
  public void successTestDateType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    Date date = new Date();
    claims.put("parameter1", date);
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(((Date)mockMessage.getClaims().get("parameter1")).getTime(), 
        date.getTime());
  }
  
  @Test
  public void successTestDateTypeConversion() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    Date date = new Date();
    claims.put("parameter1", date.getTime());
    Map<String, ParameterVerificationDefinition> parVerDef = 
        new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    Assert.assertEquals(((Date)mockMessage.getClaims().get("parameter1")).getTime(), 
        date.getTime());
  }
  
  @Test(expected = InvalidClaimException.class)
  public void failTestDateType() throws InvalidClaimException {
    HashMap<String, Object> claims = new HashMap<>();
    claims.put("parameter1", "value");
    Map<String, ParameterVerificationDefinition> parVerDef = 
         new HashMap<String, ParameterVerificationDefinition>();
    parVerDef.put("parameter1", ParameterVerification.SINGLE_OPTIONAL_DATE.getValue());
    MockMessage mockMessage = new MockMessage(claims, parVerDef);
    mockMessage.triggerVerify();
    Assert.assertEquals(mockMessage.getClaims().get("parameter1"),"value");
  }

  class MockMessage extends AbstractMessage {
    
    MockMessage(HashMap<String, Object> claims) {
      this(claims, new HashMap<String, ParameterVerificationDefinition>());
    }

    MockMessage(HashMap<String, Object> claims,
        Map<String, ParameterVerificationDefinition> parVerDef) {
      this(claims, parVerDef, new HashMap<String, List<?>>());
    }
    
    MockMessage(HashMap<String, Object> claims,
        Map<String, ParameterVerificationDefinition> parVerDef,
        Map<String, List<?>> allowedValues) {
      super(claims);
      for (String key : parVerDef.keySet()) {
        this.paramVerDefs.put(key, parVerDef.get(key));
      }
      for (String key : allowedValues.keySet()) {
        this.allowedValues.put(key, allowedValues.get(key));
      }
    }
    

    public void triggerVerify() throws InvalidClaimException {
      verify();
    }
  }
}