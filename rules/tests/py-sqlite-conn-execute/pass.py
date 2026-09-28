row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
