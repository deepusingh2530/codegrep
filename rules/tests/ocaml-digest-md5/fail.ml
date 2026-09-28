let hash s =
  Digest.to_hex (Digest.string s)
