public class Resolver {
  public Object resolve() throws Exception {
    InitialContext ctx = new InitialContext();
    return ctx.lookup("java:comp/env/jdbc/mydb");
  }
}
