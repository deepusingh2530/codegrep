async with session.get(url, ssl=False) as r:
    body = await r.read()
