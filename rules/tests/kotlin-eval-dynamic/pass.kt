fun greet(): Any? {
  val engine = ScriptEngineManager().getEngineByName("js")
  return engine.eval("\"hello\"")
}
