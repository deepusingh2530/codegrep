function issue(user) {
  return jwt.sign({ id: user.id }, "supersecretkey");
}
