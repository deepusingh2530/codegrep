resource "aws_security_group" "db" {
  ingress {
    from_port = 3389
    to_port   = 3389
  }
}
