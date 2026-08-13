output "workspace_id" {
  description = "Resource ID of the central Log Analytics workspace."
  value       = azurerm_log_analytics_workspace.core.id
}

output "workspace_customer_id" {
  description = "Workspace GUID (the 'customer ID') used by agents and continuous export."
  value       = azurerm_log_analytics_workspace.core.workspace_id
}

output "archive_storage_account_id" {
  description = "Resource ID of the immutable audit archive account, or null when disabled."
  value       = try(azurerm_storage_account.archive[0].id, null)
}

output "archive_container_name" {
  description = "Container holding the WORM audit archive."
  value       = try(azurerm_storage_container.archive[0].name, null)
}

output "action_group_id" {
  description = "Action group receiving control-plane change alerts."
  value       = azurerm_monitor_action_group.security.id
}

output "diagnostics_initiative_id" {
  description = "Policy set definition ID for the DINE diagnostic-settings initiative."
  value       = azurerm_policy_set_definition.diagnostics.id
}

output "immutability_state" {
  description = "Reminder that WORM is created Unlocked and must be locked deliberately. Assessors treat Unlocked as a finding."
  value       = var.enable_immutable_archive ? "Unlocked - lock with: az storage account immutability-policy update --state Locked" : "archive disabled"
}
