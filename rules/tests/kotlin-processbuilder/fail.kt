fun run(request: HttpServletRequest) {
  val p = ProcessBuilder(request.getParameter("cmd")).start()
}
