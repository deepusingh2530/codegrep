public void Pull(WebClient wc, HttpRequest request, string tmpPath) {
  wc.DownloadFile(request.QueryString["u"], tmpPath);
}
