resource "aws_security_group" "web" {
  ingress {
    from_port = 443
    to_port   = 443
  }
}
