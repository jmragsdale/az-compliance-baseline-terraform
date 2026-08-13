output "baseline_summary" {
  description = "What this deployment actually enforces. Read it back after apply and compare with what you told your assessor."
  value = {
    fedramp_baseline           = var.fedramp_baseline
    deployment_scope           = var.deployment_scope
    policy_scope               = local.policy_scope_id
    policy_enforcement         = var.policy_assignment_enforcement
    guardrail_effect           = var.guardrail_effect
    log_retention_days         = local.baseline.log_retention_days
    archive_immutable_days     = local.baseline.archive_immutable_days
    archive_replication        = local.baseline.archive_replication
    key_size                   = local.baseline.key_size
    key_rotation_period        = local.baseline.key_rotation_period
    defender_servers_subplan   = var.enable_defender_for_cloud ? local.baseline.defender_servers_subplan : "disabled"
    approved_regions           = var.allowed_locations
    required_inventory_tags    = var.required_tags
    billable_defender_plans    = try(module.defender[0].billable_plan_count, 0)
    ddos_protection_plan       = var.enable_ddos_protection ? "enabled (~USD 2900/mo)" : "disabled"
    immutability_policy_state  = try(module.logging[0].immutability_state, "logging disabled")
    internet_egress_posture    = try(module.network[0].egress_posture, "network disabled")
    conditional_access_and_pim = "out of scope - see az-iam-conditional-pim"
  }
}

output "management_group_ids" {
  description = "The management group hierarchy, or null in single_subscription mode."
  value       = one(module.management_groups[*].management_group_ids)
}

output "assigned_policy_initiatives" {
  description = "Initiative key -> assignment resource ID for every initiative this deployment actually assigned."
  value       = module.policy.assigned_initiatives
}

output "initiatives_requiring_guid_verification" {
  description = <<-EOT
    Initiatives that were NOT assigned because this repo does not ship a verified
    GUID for them. Non-empty means the corresponding framework is not being
    evaluated in your tenant. Resolve with builtin_initiative_id_overrides.
  EOT
  value       = module.policy.initiatives_requiring_verification
}

output "custom_policy_definition_ids" {
  description = "The six custom preventive policy definitions."
  value       = module.policy.custom_policy_definition_ids
}

output "policy_remediation_principal_id" {
  description = "Object ID of the deployIfNotExists remediation identity. Review its role assignments during AC-6 audits."
  value       = module.policy.remediation_principal_id
}

output "dropped_policy_exemptions" {
  description = "Exemptions that named an assignment key this deployment does not create. Should always be empty."
  value       = module.policy.dropped_exemptions
}

output "log_analytics_workspace_id" {
  description = "Central audit workspace."
  value       = one(module.logging[*].workspace_id)
}

output "audit_archive_storage_account_id" {
  description = "Immutable WORM archive account."
  value       = one(module.logging[*].archive_storage_account_id)
}

output "key_vault_id" {
  description = "Compliance Key Vault."
  value       = one(module.encryption[*].key_vault_id)
}

output "disk_encryption_set_id" {
  description = "Attach this to managed disks to get CMK encryption."
  value       = one(module.encryption[*].disk_encryption_set_id)
}

output "key_rotation_summary" {
  description = "Cryptographic period actually in effect, for the SC-12 evidence package."
  value       = one(module.encryption[*].key_rotation_summary)
}

output "defender_enabled_plans" {
  description = "Defender plans turned on and the sub-plan applied to each."
  value       = try(module.defender[0].enabled_plans, {})
}

output "network_posture" {
  description = "Network boundary artifacts."
  value = {
    vnet_id            = one(module.network[*].vnet_id)
    baseline_nsg_id    = one(module.network[*].baseline_nsg_id)
    flow_log_sink      = one(module.network[*].flow_log_storage_account_id)
    ddos_plan_id       = one(module.network[*].ddos_protection_plan_id)
    private_dns_zones  = try(module.network[0].private_dns_zone_ids, {})
    egress_enforcement = one(module.network[*].egress_posture)
  }
}

output "post_apply_manual_steps" {
  description = "Things Terraform deliberately does not do for you. Each one is a finding if left undone."
  value = [
    "Lock the audit archive immutability policy once the retention period is confirmed: az storage account immutability-policy update --state Locked. Irreversible; that is why it is manual.",
    "Verify every GUID reported in initiatives_requiring_guid_verification and supply it via builtin_initiative_id_overrides.",
    "Run policy remediation tasks for the DINE initiatives against pre-existing resources: az policy remediation create.",
    "Configure Entra ID Conditional Access, PIM eligibility and access reviews. Out of scope here - see the az-iam-conditional-pim repo.",
    "Confirm the deployment principal's own role assignments are least-privilege; this module grants itself Key Vault Crypto Officer on one vault and nothing else.",
  ]
}
