public class XmlIn {
  public void Load() {
    var s = new XmlReaderSettings();
    s.DtdProcessing = DtdProcessing.Ignore;
  }
}
