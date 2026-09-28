fun read(json: String): User {
  return Json.decodeFromString<User>(json)
}
