protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
  request.getRequestDispatcher(request.getParameter("next")).forward(request, response);
}
