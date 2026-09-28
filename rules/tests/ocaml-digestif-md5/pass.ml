let hash s =
  Digestif.SHA256.(to_hex (digest_string s))
