q = request.args.get('q')
q = escape_sql(q)
cursor.execute(q)
