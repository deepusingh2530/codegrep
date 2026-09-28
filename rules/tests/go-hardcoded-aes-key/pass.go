func newCipher(keyBytes []byte) (cipher.Block, error) {
    return aes.NewCipher(keyBytes)
}
