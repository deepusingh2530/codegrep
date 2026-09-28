resource "aws_cloudtrail" "t" {
  name                  = "main"
  is_multi_region_trail = true
}
