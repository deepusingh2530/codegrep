public byte[] Iv(IConfiguration config) {
  return Convert.FromBase64String(config["IvB64"]);
}
