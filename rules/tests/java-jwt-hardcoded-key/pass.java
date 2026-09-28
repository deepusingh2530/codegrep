public String issue(String id, byte[] keyBytes) {
  return Jwts.parser().setSigningKey(keyBytes).compact();
}
