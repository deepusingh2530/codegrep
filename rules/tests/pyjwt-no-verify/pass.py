data = jwt.decode(tok, key=SECRET, algorithms=["HS256"])
