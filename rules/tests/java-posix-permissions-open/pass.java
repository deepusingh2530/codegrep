public void open(Path path) throws Exception {
  Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"));
}
