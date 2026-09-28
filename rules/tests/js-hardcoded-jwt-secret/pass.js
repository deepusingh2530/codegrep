function issue(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_SECRET);
}
