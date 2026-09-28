public class Resolver {
  public Object resolve(HttpServletRequest request) throws Exception {
    InitialContext ctx = new InitialContext();
    return ctx.lookup(request.getParameter("jndiName"));
  }
}
