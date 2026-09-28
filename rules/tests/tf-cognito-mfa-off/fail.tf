resource "aws_cognito_user_pool" "p" {
  mfa_configuration = "OFF"
}
