public byte[] Derive(string password, byte[] salt) {
  var kdf = new Rfc2898DeriveBytes(password, salt, 600000);
  return kdf.GetBytes(32);
}
