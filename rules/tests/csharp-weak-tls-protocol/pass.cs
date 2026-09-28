using System.Net;
public class TlsCfg {
  public void Go() {
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
  }
}
