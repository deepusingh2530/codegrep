public class JsonConfig {
  public void configure(ObjectMapper mapper) {
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
  }
}
