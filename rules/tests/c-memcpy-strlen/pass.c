void dup(char *dst, const char *src, size_t cap) {
  size_t n = strnlen(src, cap - 1);
  memcpy(dst, src, n);
}
