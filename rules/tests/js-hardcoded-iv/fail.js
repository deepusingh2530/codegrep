function encrypt(key, plaintext) {
  const c = createCipheriv("aes-256-cbc", key, "0123456789abcdef");
  return c.update(plaintext);
}
