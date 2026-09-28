const key = crypto.pbkdf2Sync(password, "", 100000, 32, "sha256");
