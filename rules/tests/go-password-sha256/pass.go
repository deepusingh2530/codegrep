func checksum(payload []byte) [32]byte {
    return sha256.Sum256([]byte(payload))
}
