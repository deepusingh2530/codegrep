public class JsonConfig {
  public void configure(ObjectMapper mapper) {
    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
  }
}
