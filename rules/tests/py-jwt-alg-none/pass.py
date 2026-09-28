def parse(token, key):
    claims = jwt.decode(token, key, algorithms=["HS256"])
    return claims
