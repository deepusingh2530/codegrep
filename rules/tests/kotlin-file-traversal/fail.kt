fun open(intent: Intent): File {
  return File(intent.getStringExtra("path"))
}
