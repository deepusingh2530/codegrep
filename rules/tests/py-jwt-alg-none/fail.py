def parse(token, key):
    claims = jwt.decode(token, key, algorithms=["none"])
    return claims
