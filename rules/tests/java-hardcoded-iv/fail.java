public byte[] encrypt(byte[] key, byte[] plain) throws Exception {
  IvParameterSpec iv = new IvParameterSpec("0123456789abcdef".getBytes());
  Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
  c.init(Cipher.ENCRYPT_MODE, key, iv);
  return c.doFinal(plain);
}
