User.find({ "$where": "this.age > 30" }, (err, users) => {});
