public class Files2 {
  public Path resolve(HttpServletRequest request) {
    return Paths.get(request.getParameter("file"));
  }
}
