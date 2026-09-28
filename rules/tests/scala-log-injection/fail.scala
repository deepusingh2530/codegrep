class Api {
  def log(request: Request[AnyContent]) = {
    logger.info("search: " + request.getQueryString("q").get)
  }
}
