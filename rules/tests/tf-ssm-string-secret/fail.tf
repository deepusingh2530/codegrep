resource "aws_ssm_parameter" "secret" {
  name  = "/app/password"
  type  = "String"
  value = var.db_password
}
