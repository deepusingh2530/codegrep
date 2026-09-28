public class Audit {
  public void log(HttpServletRequest request) {
    LOGGER.info("user: " + request.getParameter("user"));
  }
}
