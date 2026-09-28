public Mono<String> fetch(String id) {
  return client.get().uri("/api/items/{id}", id).retrieve().bodyToMono(String.class);
}
