resource "aws_s3_bucket" "uploads" {
  bucket = "uploads"
  acl    = "private"
}
