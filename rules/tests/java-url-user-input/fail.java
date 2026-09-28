public class Fetcher {
  public void fetch(HttpServletRequest request) throws Exception {
    URL u = new URL(request.getParameter("target"));
  }
}
