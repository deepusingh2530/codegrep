resource "azurerm_network_security_rule" "ssh" {
  destination_port_range = "22"
  source_address_prefix = "*"
}
