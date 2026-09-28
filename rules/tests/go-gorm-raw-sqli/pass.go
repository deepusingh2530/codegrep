func findUser(db *gorm.DB, id int64) {
    rows := db.Raw("SELECT * FROM users WHERE id = ?", id)
    _ = rows
}
