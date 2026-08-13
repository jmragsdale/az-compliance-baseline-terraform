output "assigned_initiatives" {
  description = "Initiative key -> policy assignment resource ID for everything actually assigned."
  value       = local.assignment_ids
}

output "initiatives_requiring_verification" {
  description = <<-EOT
    Initiative key -> why it was skipped. Non-empty means this deployment is NOT
    evaluating that framework. Resolve by supplying the GUID via
    builtin_initiative_id_overrides after confirming it with:
      az policy set-definition list --query "[?displayName=='<name>'].name" -o tsv
  EOT
  value       = local.skipped_initiatives
}

output "remediation_principal_id" {
  description = "Object ID of the user-assigned identity used by deployIfNotExists remediation tasks."
  value       = azurerm_user_assigned_identity.remediation.principal_id
}

output "remediation_identity_id" {
  description = "Resource ID of the remediation user-assigned identity."
  value       = azurerm_user_assigned_identity.remediation.id
}

output "custom_guardrail_set_id" {
  description = "Resource ID of the custom guardrail policy set definition."
  value       = azurerm_policy_set_definition.custom_guardrails.id
}

output "custom_policy_definition_ids" {
  description = "Custom policy definitions created by this module."
  value = {
    allowed_locations  = azurerm_policy_definition.allowed_locations.id
    allowed_vm_skus    = azurerm_policy_definition.allowed_vm_skus.id
    required_tags      = azurerm_policy_definition.required_tags.id
    min_tls_version    = azurerm_policy_definition.min_tls_version.id
    deny_public_blob   = azurerm_policy_definition.deny_public_blob.id
    deny_public_ip_nic = azurerm_policy_definition.deny_public_ip_nic.id
  }
}

output "dropped_exemptions" {
  description = "Exemptions in var.exemptions that named an assignment this deployment does not create. Non-empty is usually a typo."
  value       = local.dropped_exemptions
}
