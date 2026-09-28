app.get("/search", (req, res) => {
  const re = new RegExp(req.query.p);
  res.json(re.exec(req.query.q));
});
