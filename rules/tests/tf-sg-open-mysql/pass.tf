resource "aws_security_group" "db" {
  ingress {
    from_port = 5432
    to_port   = 5432
  }
}
