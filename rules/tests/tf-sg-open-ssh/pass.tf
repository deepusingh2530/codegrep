resource "aws_security_group" "sg" {
  ingress {
    from_port = 443
    to_port   = 443
  }
}
