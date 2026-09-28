public String fetch(HttpServletRequest request) throws Exception {
  HttpGet get = new HttpGet(request.getParameter("u"));
  return EntityUtils.toString(client.execute(get));
}
