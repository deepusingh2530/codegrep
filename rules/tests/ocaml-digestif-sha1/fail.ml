let hash s =
  Digestif.SHA1.(to_hex (digest_string s))
