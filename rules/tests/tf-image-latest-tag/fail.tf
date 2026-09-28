resource "aws_ecs_task_definition" "td" {
  container_definitions = <<EOF
[{"image": "nginx:latest"}]
EOF
}
