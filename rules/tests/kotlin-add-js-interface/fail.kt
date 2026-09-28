fun setup(webView: WebView) {
  webView.addJavascriptInterface(this, "bridge")
}
