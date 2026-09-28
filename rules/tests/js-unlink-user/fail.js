app.delete("/x", (req) => {
  fs.unlink(req.query.file);
  fs.rm(req.body.path);
});
