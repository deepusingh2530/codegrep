function cleanup(tmpPath) {
  fs.unlink(tmpPath);
  fs.rm(oldPath);
}
