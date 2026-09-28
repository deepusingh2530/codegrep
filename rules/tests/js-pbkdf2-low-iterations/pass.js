const key = crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256", cb);
