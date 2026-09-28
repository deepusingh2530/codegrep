resource "azurerm_network_security_rule" "web" {
  destination_port_range = "443"
}
