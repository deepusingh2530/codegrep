conn.execute("SELECT * FROM users WHERE id=?1", &[&uid])?;
