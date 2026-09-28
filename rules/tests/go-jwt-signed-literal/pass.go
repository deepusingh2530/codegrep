token, _ := jwt.NewWithClaims(claims).SignedString([]byte(os.Getenv("JWT_KEY")))
