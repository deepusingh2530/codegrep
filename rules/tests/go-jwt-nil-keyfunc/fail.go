func parse(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, nil)
}
