resource "google_sql_database_instance" "db" {
  settings {
    backup_configuration {
      enabled = true
    }
  }
}
