def issue(payload):
    return jwt.encode(payload, None, algorithm="none")
