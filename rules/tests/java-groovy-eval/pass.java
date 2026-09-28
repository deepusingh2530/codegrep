public class ScriptRunner {
  public GroovyShell newShell(ClassLoader cl) {
    return new GroovyShell(cl);
  }
}
