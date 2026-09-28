token = JWT.encode(payload, ENV.fetch("JWT_SECRET"))
