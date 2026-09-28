public class Audit {
  public void Log(ILogger _logger, HttpRequest request) {
    _logger.LogInformation("user: " + request.QueryString["u"]);
  }
}
