resource "aws_lb" "alb" {
  access_logs {
    bucket  = "lb-logs"
    enabled = false
  }
}
