public class Rules {
  public Object apply(JexlEngine engine, String expr, JexlContext ctx) {
    return engine.createExpression(expr).evaluate(ctx);
  }
}
