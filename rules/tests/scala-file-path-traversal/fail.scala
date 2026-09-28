class Downloads {
  def open(request: Request[AnyContent]) = {
    val f = new File(request.getQueryString("path").get)
    f.exists()
  }
}
