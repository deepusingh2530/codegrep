public class Audit {
  public void Log(ILogger _logger) {
    _logger.LogInformation("server started");
  }
}
