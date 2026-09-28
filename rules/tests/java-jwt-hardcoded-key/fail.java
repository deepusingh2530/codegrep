public String issue(String id) {
  return Jwts.parser().setSigningKey("supersecretkey123").compact();
}
