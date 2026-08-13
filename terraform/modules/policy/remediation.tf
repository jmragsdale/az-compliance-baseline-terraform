# ---------------------------------------------------------------------------
# Remediation identity for deployIfNotExists / modify policies.
#
# Why user-assigned rather than system-assigned: a system-assigned identity is
# created and destroyed with its assignment, so every re-assignment produces a
# new principal, orphans the old role assignments, and silently breaks
# remediation until someone notices the dashboard has been red for a month. One
# long-lived user-assigned identity with explicit, reviewable role assignments is
# the auditable option.
#
# AC-6(1) least privilege is in tension with DINE here and the tension is real:
# Microsoft's own FedRAMP and NIST initiatives contain remediation tasks that
# deploy agents, write diagnostic settings and modify resource properties, which
# collectively require Contributor. The mitigations applied below are:
#   - a dedicated identity that no human can sign in as (AC-2(7))
#   - role assignments scoped to the baseline's MG/subscription, never tenant root
#   - Security Admin granted separately so Defender configuration does not
#     require Owner
# If your assessor will not accept Contributor for the remediation principal,
# set enforcement to DoNotEnforce and remediate through a change process instead.
# ---------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "remediation" {
  name                = "id-${var.name_prefix}-policy-remediation"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

locals {
  # Well-known built-in role definition IDs. These are tenant-invariant GUIDs,
  # unlike policy set definitions -- hard-coding them is safe. Using the GUID
  # rather than role_definition_name avoids a lookup that needs directory read.
  role_ids = {
    contributor = "b24988ac-6180-42a0-ab88-20f7382dd24c"
    # Security Admin: manage Defender for Cloud settings and dismiss
    # recommendations without granting resource write access.
    security_admin = "fb1c8493-542b-48eb-b624-b4c8fea62acd"
    # Log Analytics Contributor: needed by DINE policies that attach diagnostic
    # settings and deploy the Azure Monitor Agent.
    log_analytics_contributor = "92aaf0da-9dab-42b6-94a3-d43ce8d16293"
    # Monitoring Contributor: diagnostic settings on resources whose provider
    # does not fall under Log Analytics Contributor.
    monitoring_contributor = "749f88d5-cbae-40b8-bcfc-e573ddc772fa"
  }
}

# --- Management group scope -------------------------------------------------

resource "azurerm_role_assignment" "remediation_contributor_mg" {
  count = local.mg_scope ? 1 : 0

  scope              = var.management_group_id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_ids.contributor}"
  principal_id       = azurerm_user_assigned_identity.remediation.principal_id
  principal_type     = "ServicePrincipal"

  description = "AC-6(1): scoped to the baseline MG, never tenant root. Required by the deployIfNotExists tasks inside the FedRAMP/NIST built-in initiatives."
}

resource "azurerm_role_assignment" "remediation_security_admin_mg" {
  count = local.mg_scope ? 1 : 0

  scope              = var.management_group_id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_ids.security_admin}"
  principal_id       = azurerm_user_assigned_identity.remediation.principal_id
  principal_type     = "ServicePrincipal"

  description = "Lets remediation configure Defender for Cloud plans and auto-provisioning without holding Owner. CA-7 continuous monitoring."
}

resource "azurerm_role_assignment" "remediation_monitoring_mg" {
  for_each = local.mg_scope ? {
    log_analytics = local.role_ids.log_analytics_contributor
    monitoring    = local.role_ids.monitoring_contributor
  } : {}

  scope              = var.management_group_id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${each.value}"
  principal_id       = azurerm_user_assigned_identity.remediation.principal_id
  principal_type     = "ServicePrincipal"

  description = "AU-2 / AU-12: required by the DINE policies that attach diagnostic settings so audit records are generated without per-resource manual work."
}

# --- Single subscription scope ----------------------------------------------

resource "azurerm_role_assignment" "remediation_contributor_sub" {
  count = local.mg_scope ? 0 : 1

  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_ids.contributor}"
  principal_id       = azurerm_user_assigned_identity.remediation.principal_id
  principal_type     = "ServicePrincipal"

  description = "AC-6(1): remediation identity confined to a single subscription in single_subscription mode."
}

resource "azurerm_role_assignment" "remediation_security_admin_sub" {
  count = local.mg_scope ? 0 : 1

  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_ids.security_admin}"
  principal_id       = azurerm_user_assigned_identity.remediation.principal_id
  principal_type     = "ServicePrincipal"

  description = "Defender for Cloud configuration rights without Owner."
}

resource "azurerm_role_assignment" "remediation_monitoring_sub" {
  for_each = local.mg_scope ? {} : {
    log_analytics = local.role_ids.log_analytics_contributor
    monitoring    = local.role_ids.monitoring_contributor
  }

  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${each.value}"
  principal_id       = azurerm_user_assigned_identity.remediation.principal_id
  principal_type     = "ServicePrincipal"

  description = "AU-2 / AU-12: diagnostic settings remediation rights."
}
