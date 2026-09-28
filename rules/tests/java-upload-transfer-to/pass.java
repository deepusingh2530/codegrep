public void handle(InputStream in, Path out) throws Exception {
  Files.copy(in, out);
}
