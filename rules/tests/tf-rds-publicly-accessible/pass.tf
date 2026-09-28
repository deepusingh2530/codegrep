resource "aws_db_instance" "db" {
  engine               = "postgres"
  publicly_accessible  = false
}
