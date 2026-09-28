class Crypto {
  def cipher() = {
    val c = Cipher.getInstance("DES/ECB/PKCS5Padding")
    c
  }
}
