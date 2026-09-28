func findUser(db *gorm.DB, id int64) {
    rows := db.Raw(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
    _ = rows
}
