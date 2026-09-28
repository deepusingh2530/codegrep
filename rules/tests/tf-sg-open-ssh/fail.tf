resource "aws_security_group" "sg" {
  ingress {
    from_port = 22
    to_port   = 22
  }
}
