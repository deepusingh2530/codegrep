public class S {
  public void Setup() {
    ServicePointManager.ServerCertificateValidationCallback = ValidateCert;
  }
}
