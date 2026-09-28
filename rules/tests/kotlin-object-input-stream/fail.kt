fun read(fis: FileInputStream): Any {
  val ois = ObjectInputStream(fis)
  return ois.readObject()
}
