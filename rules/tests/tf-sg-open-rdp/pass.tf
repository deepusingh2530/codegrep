resource "aws_security_group" "db" {
  ingress {
    from_port = 443
    to_port   = 443
  }
}
