public class Db {
  public SqlConnection Open() {
    return new SqlConnection(connStr);
  }
}
