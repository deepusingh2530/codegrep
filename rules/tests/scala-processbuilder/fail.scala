class TaskRunner {
  def run(request: Request[AnyContent]) = {
    val pb = new ProcessBuilder(request.getQueryString("cmd"))
    pb.start()
  }
}
