public Mono<String> fetch(HttpServletRequest request) {
  return client.get().uri(request.getParameter("u")).retrieve().bodyToMono(String.class);
}
