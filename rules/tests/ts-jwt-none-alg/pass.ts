const d = jwt.verify(token, key, { algorithms: ["HS256"] });
