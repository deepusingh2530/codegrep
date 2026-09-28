public class S {
  public void Setup() {
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
  }
}
