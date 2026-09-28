def digest(data):
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()
