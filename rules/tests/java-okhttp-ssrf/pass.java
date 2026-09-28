public class Fetcher {
  public void fetch() throws Exception {
    URI uri = URI.create("/health");
    Request rq = new Request.Builder().url("https://api.example.com").build();
  }
}
