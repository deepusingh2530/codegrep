fun cipher(): Cipher {
  return Cipher.getInstance("AES/GCM/NoPadding")
}
