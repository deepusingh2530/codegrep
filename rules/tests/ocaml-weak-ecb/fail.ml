let cipher ~key =
  Cryptokit.Cipher.aes ~key ~mode:`ECB
