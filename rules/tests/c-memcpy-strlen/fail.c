void dup(char *dst, const char *src) {
  memcpy(dst, src, strlen(src) + 1);
}
