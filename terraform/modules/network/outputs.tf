output "vnet_id" {
  description = "Resource ID of the platform VNet."
  value       = azurerm_virtual_network.platform.id
}

output "private_endpoint_subnet_id" {
  description = "Subnet private endpoints are placed in."
  value       = azurerm_subnet.private_endpoints.id
}

output "baseline_nsg_id" {
  description = "Resource ID of the deny-by-default baseline NSG."
  value       = azurerm_network_security_group.baseline.id
}

output "network_watcher_id" {
  description = "Network Watcher resource ID, or null when not created by this module."
  value       = try(azurerm_network_watcher.this[0].id, null)
}

output "flow_log_storage_account_id" {
  description = "Flow log sink storage account, or null when flow logs are disabled."
  value       = try(azurerm_storage_account.flow_logs[0].id, null)
}

output "ddos_protection_plan_id" {
  description = "DDoS protection plan, or null when disabled."
  value       = try(azurerm_network_ddos_protection_plan.this[0].id, null)
}

output "private_dns_zone_ids" {
  description = "Private DNS zones created for private endpoints."
  value       = { for k, v in azurerm_private_dns_zone.this : k => v.id }
}

output "egress_posture" {
  description = "Whether the explicit internet egress deny is active. \"permissive\" means Azure's default AllowInternetOutBound still applies."
  value       = var.deny_internet_egress ? "deny-by-default" : "permissive"
}
