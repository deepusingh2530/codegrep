let cipher ~key ~iv =
  Cryptokit.Cipher.aes ~key ~iv ~mode:`CTR
