# ---------------------------------------------------------------------------
# Private endpoints and private DNS.
#
# SC-7(3) limits external connections to managed interfaces. A Key Vault or
# storage account with a public endpoint -- even one behind a firewall allowlist
# -- is reachable from the internet by definition, and the allowlist is a control
# that fails open if someone widens it.
#
# The private DNS zone is the part people forget. Without it, the client resolves
# the public name to a public IP and the private endpoint is a NIC nobody uses,
# while the traffic quietly continues to traverse the internet. The zone, the
# VNet link and the endpoint's zone group are all required for this to be a
# control rather than a diagram.
# ---------------------------------------------------------------------------

resource "azurerm_private_dns_zone" "this" {
  for_each = local.private_dns_zones

  name                = each.value
  resource_group_name = var.resource_group_name

  tags = merge(var.tags, { "control-family" = "SC-7" })
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each = local.private_dns_zones

  name                  = "link-${each.key}-platform"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.this[each.key].name
  virtual_network_id    = azurerm_virtual_network.platform.id

  # Autoregistration off: these zones hold privatelink records managed by the
  # endpoints, not VM A-records. Mixing the two makes the zone unreviewable.
  registration_enabled = false

  tags = var.tags
}

resource "azurerm_private_endpoint" "key_vault" {
  count = var.enable_private_endpoints && var.key_vault_id != null ? 1 : 0

  name                = "pe-${var.name_prefix}-keyvault"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "psc-keyvault"
    private_connection_resource_id = var.key_vault_id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "dns-keyvault"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["key_vault"].id]
  }

  tags = merge(var.tags, { "control-family" = "SC-7" })
}

resource "azurerm_private_endpoint" "archive_blob" {
  count = var.enable_private_endpoints && var.archive_storage_account_id != null ? 1 : 0

  name                = "pe-${var.name_prefix}-archive-blob"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "psc-archive-blob"
    private_connection_resource_id = var.archive_storage_account_id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "dns-blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["blob"].id]
  }

  tags = merge(var.tags, { "control-family" = "SC-7" })
}
