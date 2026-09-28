public class JwtKey {
  public SymmetricSecurityKey Key(byte[] keyBytes) {
    return new SymmetricSecurityKey(keyBytes);
  }
}
