conn.execute(&format!("SELECT * FROM users WHERE id={}", uid))?;
