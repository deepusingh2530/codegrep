public void Pull(WebClient wc, string tmpPath) {
  wc.DownloadFile("https://example.com/data.json", tmpPath);
}
