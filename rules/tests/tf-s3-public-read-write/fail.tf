resource "aws_s3_bucket" "uploads" {
  bucket = "uploads"
  acl    = "public-read-write"
}
