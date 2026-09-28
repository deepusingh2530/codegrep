func newCipher() (cipher.Block, error) {
    return aes.NewCipher([]byte("supersecretkey12"))
}
