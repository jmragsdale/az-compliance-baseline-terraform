output "enabled_plans" {
  description = "Defender plans this deployment turned on, with the sub-plan actually applied."
  value       = { for k, v in local.enabled_plans : k => coalesce(v.subplan, v.tier) }
}

output "billable_plan_count" {
  description = "How many metered Defender plans are enabled. Zero is a valid and free posture."
  value       = length(local.enabled_plans)
}

output "servers_plan_tier" {
  description = "Defender for Servers tier in effect. P2 is required for the agent-based vulnerability assessment and file integrity monitoring that RA-5 and SI-7 expect."
  value       = var.enable_servers ? var.servers_subplan : "disabled"
}

output "continuous_export_targets" {
  description = "Where Defender findings are being exported."
  value = compact([
    var.enable_continuous_export ? "log-analytics" : "",
    (var.enable_continuous_export && var.event_hub_resource_id != null && var.event_hub_connection_string != null) ? "event-hub" : "",
  ])
}

output "custom_assessment_id" {
  description = "Custom Defender assessment checking that the audit archive WORM policy is locked."
  value       = azurerm_security_center_assessment_policy.worm_lock.id
}
