public class Db {
  public SqlConnection Open() {
    return new SqlConnection("Server=db;Database=app;User Id=sa;Password=hunter2;");
  }
}
