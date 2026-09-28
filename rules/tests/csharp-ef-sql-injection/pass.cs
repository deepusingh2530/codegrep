public void Find(AppDb db) {
  db.Users.FromSqlRaw("SELECT * FROM users WHERE active = 1");
}
