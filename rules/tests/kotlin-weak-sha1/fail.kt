fun digest(data: ByteArray): ByteArray {
  val md = MessageDigest.getInstance("SHA1")
  return md.digest(data)
}
