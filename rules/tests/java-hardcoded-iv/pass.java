public byte[] encrypt(byte[] key, byte[] iv, byte[] plain) throws Exception {
  IvParameterSpec spec = new IvParameterSpec(iv);
  Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
  c.init(Cipher.ENCRYPT_MODE, key, spec);
  return c.doFinal(plain);
}
