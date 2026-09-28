def get_q():
    return request.args.get('q')

q = get_q()
cursor.execute(q)
