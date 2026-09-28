app.post("/move", (req, res) => {
  fs.copyFile(src, req.query.dest, cb);
  res.end();
});
