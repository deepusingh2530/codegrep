public String view(Context ctx) {
  return templateEngine.process("welcome", ctx);
}
