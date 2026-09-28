fun digest(data: ByteArray): ByteArray {
  val md = MessageDigest.getInstance("SHA-256")
  return md.digest(data)
}
