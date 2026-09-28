public String fetch() throws Exception {
  HttpGet get = new HttpGet("https://api.example.com/health");
  return EntityUtils.toString(client.execute(get));
}
