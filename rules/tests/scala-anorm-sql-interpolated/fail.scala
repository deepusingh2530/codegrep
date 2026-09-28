class Users {
  def find(userId: Long) = DB.withConnection { implicit c =>
    sql"SELECT * FROM users WHERE id = $userId".as[User.parser.single]
  }
}
