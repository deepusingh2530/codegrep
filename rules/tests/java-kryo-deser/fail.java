public Object load(Kryo kryo, Input in) {
  return kryo.readObject(in, User.class);
}
