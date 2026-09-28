resource "aws_lambda_permission" "public" {
  action    = "lambda:InvokeFunction"
  principal = "*"
}
