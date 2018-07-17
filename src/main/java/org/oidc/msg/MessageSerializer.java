package org.oidc.msg;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class MessageSerializer extends StdSerializer<AbstractMessage> {

  public MessageSerializer() {
    this(null);
  }

  public MessageSerializer(Class<AbstractMessage> t) {
    super(t);
  }

  @Override
  public void serialize(AbstractMessage value, JsonGenerator gen, SerializerProvider provider)
      throws IOException {
    gen.writeStartObject();
    Map<String, Object> claims = value.getClaims();
    for (Entry<String, Object> entry : claims.entrySet()) {
      gen.writeObjectField(entry.getKey(), entry.getValue());
    }
    gen.writeEndObject();

  }
}
