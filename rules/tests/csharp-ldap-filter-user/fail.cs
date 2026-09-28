public void Search(HttpRequest request) {
  var ds = new DirectorySearcher();
  ds.Filter = "(uid=" + request.QueryString["u"] + ")";
}
