public class PipelineLoader {
  public Map<String, Object> loadDefaults() throws Exception {
    return configStore.readDefaults();
  }
}
