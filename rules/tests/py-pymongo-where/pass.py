def find_old_users(db):
    return db.users.find({"age": {"$gt": 30}})
