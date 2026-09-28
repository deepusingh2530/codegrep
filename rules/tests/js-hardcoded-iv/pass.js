function encrypt(key, iv, plaintext) {
  const c = createCipheriv("aes-256-cbc", key, iv);
  return c.update(plaintext);
}
