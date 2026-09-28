class Exporter {
  def write(request: Request[AnyContent]) = {
    Files.write(request.getQueryString("path").get, data)
  }
}
