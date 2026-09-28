resource "aws_lambda_permission" "apigw" {
  action    = "lambda:InvokeFunction"
  principal = "apigateway.amazonaws.com"
}
