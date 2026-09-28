fun cipher(): Cipher {
  return Cipher.getInstance("AES/ECB/PKCS5Padding")
}
