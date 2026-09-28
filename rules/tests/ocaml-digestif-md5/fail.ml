let hash s =
  Digestif.MD5.(to_hex (digest_string s))
