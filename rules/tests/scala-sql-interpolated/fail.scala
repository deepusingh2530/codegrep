val id = request.queryString("id")
stmt.execute(s"SELECT * FROM users WHERE id=$id")
