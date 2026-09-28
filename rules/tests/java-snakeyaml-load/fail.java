public class PipelineLoader {
  public Object load(InputStream in) {
    return new Yaml().load(in);
  }
}
