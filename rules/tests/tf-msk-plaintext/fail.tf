resource "aws_msk_cluster" "k" {
  broker_node_group_info {
    encryption_info {
      encryption_in_transit {
        client_broker = "PLAINTEXT"
      }
    }
  }
}
