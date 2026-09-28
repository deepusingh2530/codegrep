class Go {
  def go(request: Request[AnyContent]) = {
    Redirect(request.getQueryString("next").getOrElse("/"))
  }
}
