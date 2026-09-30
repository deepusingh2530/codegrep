local res = conn:query("SELECT * FROM accounts WHERE id = ?", {uid})
