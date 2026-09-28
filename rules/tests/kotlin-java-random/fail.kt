fun token(): Int {
  val r = java.util.Random(42)
  return r.nextInt(1000000)
}
