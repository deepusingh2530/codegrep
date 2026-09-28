class SaxXml {
  def parser() = {
    val node = xmlParser.parse(defaultSource)
    node
  }
}
