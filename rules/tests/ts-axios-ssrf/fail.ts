app.get("/proxy", async (req, res) => {
  const r = await axios.get(req.query.u);
  res.json(r.data);
});
