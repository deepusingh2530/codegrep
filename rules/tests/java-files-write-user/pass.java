public void save(Path outPath, byte[] data) throws Exception {
  Files.write(outPath, data);
}
