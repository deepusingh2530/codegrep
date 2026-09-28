class Fetcher {
  def fetch(request: Request[AnyContent]) = {
    val u = new URL(request.getQueryString("target").get)
    u.openStream()
  }
}
