class CacheLoader {
  def load(in: InputStream): String = {
    scala.io.Source.fromInputStream(in).mkString
  }
}
