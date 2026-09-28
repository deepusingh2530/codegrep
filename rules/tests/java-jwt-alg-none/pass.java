public String issue(String id, Key key) {
  return Jwts.builder().setSubject(id).signWith(SignatureAlgorithm.HS256, key).compact();
}
