payload = JWT.decode(token, key, true, algorithm: 'HS256')
