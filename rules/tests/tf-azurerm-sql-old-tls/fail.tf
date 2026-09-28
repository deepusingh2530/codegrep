resource "azurerm_mssql_server" "sql" {
  name                         = "demo"
  minimal_tls_version          = "1.0"
}
