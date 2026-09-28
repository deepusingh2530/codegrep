resource "aws_s3_bucket" "b" {
  bucket = "demo"

  versioning_configuration {
    status = "Disabled"
  }
}
