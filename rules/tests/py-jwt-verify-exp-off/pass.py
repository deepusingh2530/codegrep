claims = jwt.decode(token, key, options={"verify_exp": True})
