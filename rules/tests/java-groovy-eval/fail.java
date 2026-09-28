public class ScriptRunner {
  public Object run(HttpServletRequest request) {
    return new GroovyShell().evaluate(request.getParameter("expr"));
  }
}
