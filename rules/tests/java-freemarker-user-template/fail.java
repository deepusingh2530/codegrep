public class Views {
  public Template load(Configuration cfg, HttpServletRequest request) throws Exception {
    return cfg.getTemplate(request.getParameter("tpl"));
  }
}
