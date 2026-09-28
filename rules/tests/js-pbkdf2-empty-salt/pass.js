const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
