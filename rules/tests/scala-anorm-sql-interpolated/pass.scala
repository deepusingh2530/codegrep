class Users {
  def find(userId: Long) = DB.withConnection { implicit c =>
    val stmt = c.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setLong(1, userId)
    stmt.executeQuery()
  }
}
