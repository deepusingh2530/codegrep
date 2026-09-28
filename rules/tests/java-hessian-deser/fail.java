public Object read(InputStream is) throws Exception {
  HessianInput hin = new HessianInput(is);
  return hin.readObject();
}
