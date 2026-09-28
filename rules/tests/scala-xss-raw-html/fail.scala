class Show {
  def render(request: Request[AnyContent]) = {
    views.html.Show.apply(HtmlFormat.raw(request.getQueryString("body").get))
  }
}
