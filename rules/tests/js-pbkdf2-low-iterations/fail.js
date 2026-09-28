const key = crypto.pbkdf2Sync(password, salt, 1000, 32, "sha256", cb);
