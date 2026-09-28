public Object eval(ELContext ctx, String expr) {
  ValueExpression ve = factory.createValueExpression(ctx, expr, String.class);
  return ve.getValue(ctx);
}
