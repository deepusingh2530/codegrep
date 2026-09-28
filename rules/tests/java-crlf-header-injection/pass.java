public class TraceFilter {
  public void doFilter(HttpServletRequest request, HttpServletResponse response) {
    response.addHeader("Content-Type", "application/json");
  }
}
