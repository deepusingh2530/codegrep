class Resolver {
  def resolve() = {
    val ctx = new InitialContext()
    ctx.lookup("java:comp/env/jdbc/mydb")
  }
}
