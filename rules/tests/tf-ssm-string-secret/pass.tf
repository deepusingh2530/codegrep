resource "aws_ssm_parameter" "secret" {
  name  = "/app/password"
  type  = "SecureString"
  value = var.db_password
}
