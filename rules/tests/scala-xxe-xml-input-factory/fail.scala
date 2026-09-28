class StaxXml {
  def parser() = {
    val xif = XMLInputFactory.newInstance()
    xif.createXMLStreamReader(reader)
  }
}
