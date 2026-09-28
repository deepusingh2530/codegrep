class Fetcher {
  def fetch() = {
    val u = new URL("https://api.example.com/data")
    u.openStream()
  }
}
