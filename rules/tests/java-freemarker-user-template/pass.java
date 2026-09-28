public class Views {
  public Template load(Configuration cfg) throws Exception {
    return cfg.getTemplate("welcome.ftl");
  }
}
