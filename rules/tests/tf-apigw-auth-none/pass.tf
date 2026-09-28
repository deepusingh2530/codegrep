resource "aws_api_gateway_stage" "s" {
  authorization = "COGNITO_USER_POOLS"
}
