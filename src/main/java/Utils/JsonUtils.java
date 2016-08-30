package Utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;

import java.io.IOException;

public class JsonUtils {
    private static final ObjectMapper defaultObjectMapper = new ObjectMapper();
    private static volatile ObjectMapper objectMapper = null;

    // taken from Play framework (play.libs.Json)
    private static ObjectMapper mapper() {
        if (objectMapper == null) {
            defaultObjectMapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
            return defaultObjectMapper;
        } else {
            objectMapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
            return objectMapper;
        }
    }

    // taken from Play framework (play.libs.Json)
    public static JsonNode toJson(final Object data) {
        try {
            return mapper().valueToTree(data);
        } catch (Exception e) {
            return null;
        }
    }

    // credit goes to David Lai (from appmixture.io)
    public static <T> T fromJson(String srcJson, Class<T> destType) {
        try {
            ObjectMapper mapper = new ObjectMapper();

            // Note: this is needed to ignore deserialization on certain annotatated properties
            mapper.configure(MapperFeature.USE_GETTERS_AS_SETTERS, false);
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            return mapper.readValue(srcJson, destType);
        } catch (IOException e) {
            System.out.println("JsonUtils - fromJson(String, Class<T>) failed\n caught " + e);
        }
        return null;
    }

    // credit goes to David Lai (from appmixture.io)
    public static <T> T fromJson(String srcJson, TypeReference<T> destType) {
        try {
            return new ObjectMapper()
                    .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                    .readValue(srcJson, destType);
        } catch (IOException e) {
            System.out.println("JsonUtils - fromJson(String, TypeReference<T>) failed\n caught " + e);
        }
        return null;
    }
}
