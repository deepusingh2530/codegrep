resource "aws_security_group" "db" {
  ingress {
    from_port = 3306
    to_port   = 3306
  }
}
