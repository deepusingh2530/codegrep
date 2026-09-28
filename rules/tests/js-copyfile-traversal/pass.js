function move(src, dst, cb) {
  fs.copyFile(src, dst, cb);
}
