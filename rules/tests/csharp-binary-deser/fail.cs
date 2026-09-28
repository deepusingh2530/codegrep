public object Load(Stream fs) {
  var bf = new BinaryFormatter();
  return bf.Deserialize(fs);
}
