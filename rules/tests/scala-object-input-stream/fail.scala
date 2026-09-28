class CacheLoader {
  def load(in: InputStream): Any = {
    val ois = new ObjectInputStream(in)
    ois.readObject()
  }
}
