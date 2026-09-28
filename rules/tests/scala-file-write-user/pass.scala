class Exporter {
  def write(target: Path) = {
    Files.write(target, data)
  }
}
