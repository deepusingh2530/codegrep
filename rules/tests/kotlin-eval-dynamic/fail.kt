fun evalExpr(request: HttpServletRequest): Any? {
  val engine = ScriptEngineManager().getEngineByName("js")
  return engine.eval(request.getParameter("expr"))
}
