def issue(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")
