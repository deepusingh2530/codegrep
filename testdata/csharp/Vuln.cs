using System.Diagnostics;
using System.IO;
public class Vuln {
  void Sqli(string q) {
    var cmd = new SqlCommand(q, null);
  }
  void Cmdi(string input) {
    Process.Start(input, null);
  }
  void Xss(string name) {
    Response.Write(name);
  }
  void Trav(string p) {
    File.ReadAllText(p);
  }
  void Deser(System.Runtime.Serialization.Formatters.Binary.BinaryFormatter f, System.IO.Stream s) {
    f.Deserialize(s);
  }
}
