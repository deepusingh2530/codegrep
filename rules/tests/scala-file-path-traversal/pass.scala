class Downloads {
  def open(base: String) = {
    val f = filepath.resolve(base)
    f.exists()
  }
}
