public String view(HttpServletRequest request, Context ctx) {
  return templateEngine.process(request.getParameter("page"), ctx);
}
