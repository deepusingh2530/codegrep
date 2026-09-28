public void Find(AppDb db, HttpRequest request) {
  db.Users.FromSqlRaw("SELECT * FROM users WHERE id = " + request.QueryString["id"]);
}
