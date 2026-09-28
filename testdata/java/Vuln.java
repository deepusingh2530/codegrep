public class Vuln {
  void sqli(java.sql.Statement stmt, String q) throws Exception {
    stmt.executeQuery(q);
  }
  void cmdi(String input) throws Exception {
    Runtime.getRuntime().exec(input);
  }
  void trav(String p) throws Exception {
    new java.io.File(p);
  }
  void deser(java.io.ObjectInputStream in) throws Exception {
    in.readObject();
  }
  void xss(javax.servlet.http.HttpServletResponse res, String name) throws Exception {
    res.getWriter().write(name);
  }
}
