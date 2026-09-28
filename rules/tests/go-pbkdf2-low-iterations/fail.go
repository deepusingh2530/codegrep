key := pbkdf2.Key([]byte(pw), salt, 1000, 32, sha256.New)
