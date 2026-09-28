async with session.get(url, timeout=30) as r:
    body = await r.read()
