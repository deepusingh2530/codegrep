app.get("/comment", (req, res) => {
  $("#list").append(req.body.html);
  res.end();
});
