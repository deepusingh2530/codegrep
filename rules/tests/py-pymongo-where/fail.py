def find_old_users(db, request):
    return db.users.find({"$where": "this.age > 30"})
