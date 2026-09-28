app.get("/file", (req, res) => {
  const p = path.resolve(baseDir, req.query.file);
  res.sendFile(p);
});
