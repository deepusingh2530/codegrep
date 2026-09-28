resource "aws_elasticache_cluster" "cache" {
  cluster_id                 = "demo"
  at_rest_encryption_enabled = false
}
