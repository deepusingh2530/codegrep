app.get("/plugin", async (req, res) => {
  const m = await import(request.query.mod);
  res.json(Object.keys(m));
});
