output "root_management_group_id" {
  description = "Resource ID of the intermediate root MG. This is the policy assignment scope in management_group mode."
  value       = azurerm_management_group.root.id
}

output "management_group_ids" {
  description = "All management group resource IDs keyed by role."
  value = {
    root           = azurerm_management_group.root.id
    platform       = azurerm_management_group.platform.id
    landing_zones  = azurerm_management_group.landing_zones.id
    prod           = azurerm_management_group.prod.id
    nonprod        = azurerm_management_group.nonprod.id
    sandbox        = azurerm_management_group.sandbox.id
    decommissioned = azurerm_management_group.decommissioned.id
  }
}

output "associated_subscription_count" {
  description = "How many subscriptions this module placed into the hierarchy."
  value       = length(azurerm_management_group_subscription_association.this)
}
