public void Save(HttpRequest request, string data) {
  File.WriteAllText(uploads + request.QueryString["name"], data);
}
