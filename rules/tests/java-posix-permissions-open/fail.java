public void open(Path path) throws Exception {
  Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-rw-rwx"));
}
