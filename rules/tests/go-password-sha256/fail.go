func hashPassword(password string) [32]byte {
    return sha256.Sum256([]byte(password))
}
