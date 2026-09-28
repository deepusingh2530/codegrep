public String issue(String id) {
  return Jwts.builder().setSubject(id).signWith(SignatureAlgorithm.NONE).compact();
}
