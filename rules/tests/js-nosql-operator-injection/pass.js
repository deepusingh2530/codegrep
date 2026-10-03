User.find({ email: String(email) }, (err, users) => { res.json(users); });
