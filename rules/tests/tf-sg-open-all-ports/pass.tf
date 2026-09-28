resource "aws_security_group" "sg" {
  ingress {
    to_port = 443
  }
}
