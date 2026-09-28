class StaxXml {
  def parser() = {
    val node = xmlParser.parse(defaultSource)
    node
  }
}
