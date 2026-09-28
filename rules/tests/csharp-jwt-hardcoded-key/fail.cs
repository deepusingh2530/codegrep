public class JwtKey {
  public SymmetricSecurityKey Key() {
    return new SymmetricSecurityKey(Encoding.UTF8.GetBytes("supersecretkey123"));
  }
}
