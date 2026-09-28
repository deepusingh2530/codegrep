public class Fetcher {
  public void fetch(HttpServletRequest request) throws Exception {
    URI uri = URI.create(request.getParameter("u"));
    Request rq = new Request.Builder().url(request.getParameter("img")).build();
  }
}
