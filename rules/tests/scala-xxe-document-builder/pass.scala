class XmlDocument {
  def parser() = {
    val node = xmlParser.parse(defaultSource)
    node
  }
}
