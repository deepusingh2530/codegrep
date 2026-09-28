class SaxXml {
  def parser() = {
    val spf = SAXParserFactory.newInstance()
    spf.newSAXParser()
  }
}
