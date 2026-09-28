public void Show(XmlDocument doc, HttpRequest request) {
  var n = doc.SelectSingleNode("//item[@id='" + request.QueryString["id"] + "']");
}
