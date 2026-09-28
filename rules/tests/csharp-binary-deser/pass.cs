public T Load<T>(string json) {
  return JsonSerializer.Deserialize<T>(json);
}
