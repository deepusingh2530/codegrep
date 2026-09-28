resource "aws_ecr_repository" "repo" {
  image_scanning_configuration {
    scan_on_push = true
  }
}
