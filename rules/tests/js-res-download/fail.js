app.get("/file", (req, res) => res.download(req.query.path));
