def digest(data):
    h = MD5.new()
    h.update(data)
    return h.hexdigest()
