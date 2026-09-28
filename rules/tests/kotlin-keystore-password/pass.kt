fun open(fis: FileInputStream) {
  val ks = KeyStore.getInstance("JKS")
  ks.load(fis, null)
}
