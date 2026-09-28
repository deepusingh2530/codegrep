decoded = jwt.decode(tok, key, options = {"verify_aud": True})
