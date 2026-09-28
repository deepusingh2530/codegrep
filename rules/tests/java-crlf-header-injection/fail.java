public class TraceFilter {
  public void doFilter(HttpServletRequest request, HttpServletResponse response) {
    response.addHeader("X-Trace", request.getParameter("trace"));
  }
}
