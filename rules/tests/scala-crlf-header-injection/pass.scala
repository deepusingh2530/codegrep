class Trace {
  def apply(request: Request[AnyContent], response: Response) = {
    response.setHeader("Content-Type", "application/json")
  }
}
