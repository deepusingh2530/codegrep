resource "aws_dynamodb_table" "t" {
  point_in_time_recovery {
    enabled = false
  }
}
