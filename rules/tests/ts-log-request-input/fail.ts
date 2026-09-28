app.get("/echo", (req, res) => {
  console.log("q: " + req.query.q);
  res.end();
});
