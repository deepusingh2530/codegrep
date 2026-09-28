resource "azurerm_role_assignment" "r" {
  scope                = "/subscriptions/0000"
  role_definition_name = "Reader"
}
