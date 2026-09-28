class Trace {
  def apply(request: Request[AnyContent], response: Response) = {
    response.setHeader("X-Trace", request.getQueryString("trace").get)
  }
}
