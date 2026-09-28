class Resolver {
  def resolve(request: Request[AnyContent]) = {
    val ctx = new InitialContext()
    ctx.lookup(request.getQueryString("jndi").get)
  }
}
