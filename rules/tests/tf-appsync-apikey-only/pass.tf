resource "aws_appsync_graphql_api" "api" {
  authentication_type = "AMAZON_COGNITO_USER_POOLS"
}
