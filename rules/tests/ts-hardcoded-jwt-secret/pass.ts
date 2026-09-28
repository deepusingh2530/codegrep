const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
