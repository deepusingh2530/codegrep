package main
import "github.com/golang-jwt/jwt"
func f(tok string) { jwt.ParseUnverified(tok, nil) }
