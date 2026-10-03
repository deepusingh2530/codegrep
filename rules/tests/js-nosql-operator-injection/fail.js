User.find(req.query, (err, users) => { res.json(users); });
