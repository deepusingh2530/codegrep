func parse(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
    return jwt.Parse(tokenString, keyFunc)
}
