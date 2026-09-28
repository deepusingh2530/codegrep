class Inventory {
  def parse(userXml: String) = {
    val node = scala.xml.XML.loadString(userXml)
    node
  }
}
