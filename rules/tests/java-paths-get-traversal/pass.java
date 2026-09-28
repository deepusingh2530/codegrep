public class Files2 {
  public Path resolve(String configDir) {
    return Paths.get(configDir, "app.conf");
  }
}
