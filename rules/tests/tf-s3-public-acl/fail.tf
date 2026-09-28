resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}
