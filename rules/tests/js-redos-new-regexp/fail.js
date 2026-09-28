app.get("/search", (req, res) => {
  const re = new RegExp(req.query.pattern);
  res.json(re.exec(req.query.q));
});
