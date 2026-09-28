class Crypto {
  def cipher() = {
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c
  }
}
