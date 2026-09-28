public void save(HttpServletRequest request, byte[] data) throws Exception {
  Files.write(Paths.get(request.getParameter("p")), data);
}
public void saveOut(HttpServletRequest request) throws Exception {
  FileOutputStream fos = new FileOutputStream(request.getParameter("out"));
}
