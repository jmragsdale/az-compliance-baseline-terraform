# ---------------------------------------------------------------------------
# Composition root.
#
# Order of dependency, and why it is that order:
#
#   management-groups  no dependencies. Creates the scope everything else is
#                      assigned at. Skipped entirely in single_subscription mode.
#   encryption         no dependencies. Must exist before logging so the audit
#                      archive can be created with a customer-managed key rather
#                      than re-keyed afterwards (re-keying an account that already
#                      holds WORM data is not a supported operation).
#   policy             depends on the MG scope. Owns the remediation identity that
#                      logging's DINE initiative also uses -- one principal, one
#                      reviewable set of role assignments.
#   logging            depends on encryption (CMK) and policy (remediation identity).
#   defender           depends on logging (workspace).
#   network            depends on encryption and logging (the things it fronts
#                      with private endpoints).
# ---------------------------------------------------------------------------

resource "azurerm_resource_group" "compliance" {
  name     = local.resource_group_name
  location = var.primary_location
  tags     = local.tags
}

# ---------------------------------------------------------------------------
# AC-3 / CM-2: the enforcement topology. Gated so the whole repo plans without
# Microsoft.Management registration or tenant-root RBAC.
# ---------------------------------------------------------------------------
module "management_groups" {
  count  = local.mg_scope ? 1 : 0
  source = "./modules/management-groups"

  name_prefix                = var.name_prefix
  root_display_name          = var.root_management_group_display_name
  parent_management_group_id = var.parent_management_group_id
  subscription_associations  = var.subscription_associations
}

# ---------------------------------------------------------------------------
# SC-12 / SC-28: the root of trust. First, because everything that stores data
# wants a key from it.
# ---------------------------------------------------------------------------
module "encryption" {
  count  = var.enable_encryption ? 1 : 0
  source = "./modules/encryption"

  name_prefix         = var.name_prefix
  unique_suffix       = local.unique
  resource_group_name = azurerm_resource_group.compliance.name
  location            = var.primary_location
  tenant_id           = var.tenant_id

  fedramp_baseline    = var.fedramp_baseline
  key_size            = local.baseline.key_size
  key_rotation_period = local.baseline.key_rotation_period
  key_expiry_period   = local.baseline.key_expiry_period
  key_notify_before   = local.baseline.key_notify_before

  tags = local.tags
}

# ---------------------------------------------------------------------------
# CA-2 / CA-7 / CM-6: the regulatory initiatives and the preventive guardrails.
# Always instantiated -- it is free, and it owns the remediation identity that
# the logging module's DINE initiative depends on.
# ---------------------------------------------------------------------------
module "policy" {
  source = "./modules/policy"

  name_prefix         = var.name_prefix
  deployment_scope    = var.deployment_scope
  management_group_id = one(module.management_groups[*].root_management_group_id)
  subscription_id     = var.subscription_id
  location            = var.primary_location
  resource_group_name = azurerm_resource_group.compliance.name

  fedramp_baseline       = var.fedramp_baseline
  primary_initiative_key = local.baseline.primary_initiative_key

  builtin_initiative_id_overrides = var.builtin_initiative_id_overrides
  trust_unverified_initiative_ids = var.trust_unverified_initiative_ids
  enable_regulatory_initiatives   = var.enable_regulatory_initiatives
  enable_custom_guardrails        = var.enable_custom_guardrails
  enforcement_mode                = var.policy_assignment_enforcement
  guardrail_effect                = var.guardrail_effect

  allowed_locations    = var.allowed_locations
  allowed_vm_sku_sizes = var.allowed_vm_sku_sizes
  required_tags        = var.required_tags

  exemptions = var.policy_exemptions

  tags = local.tags
}

# ---------------------------------------------------------------------------
# AU family. The audit substrate every detective control writes into.
# ---------------------------------------------------------------------------
module "logging" {
  count  = var.enable_logging ? 1 : 0
  source = "./modules/logging"

  name_prefix         = var.name_prefix
  unique_suffix       = local.unique
  resource_group_name = azurerm_resource_group.compliance.name
  location            = var.primary_location
  secondary_location  = var.secondary_location
  subscription_id     = var.subscription_id

  deployment_scope    = var.deployment_scope
  management_group_id = one(module.management_groups[*].root_management_group_id)
  enforcement_mode    = var.policy_assignment_enforcement

  # AU-11 / CP-9, baseline-driven.
  log_retention_days     = local.baseline.log_retention_days
  archive_immutable_days = local.baseline.archive_immutable_days
  archive_replication    = local.baseline.archive_replication
  blob_soft_delete_days  = local.baseline.blob_soft_delete_days
  daily_quota_gb         = var.log_analytics_daily_quota_gb

  enable_immutable_archive = var.enable_immutable_archive
  enable_event_hub_export  = var.enable_event_hub_export

  event_hub_authorization_rule_id = var.event_hub_authorization_rule_id
  event_hub_name                  = var.event_hub_name

  remediation_identity_id   = module.policy.remediation_identity_id
  alert_notification_emails = var.alert_notification_emails

  # SC-28(1): the audit archive is encrypted with a key this tenant controls, so
  # key destruction is an available sanitisation path (MP-6).
  key_vault_id         = one(module.encryption[*].key_vault_id)
  cmk_key_vault_key_id = one(module.encryption[*].storage_cmk_id)
  cmk_identity_id      = one(module.encryption[*].cmk_identity_id)

  tags = local.tags
}

# ---------------------------------------------------------------------------
# RA-5 / SI-4 / CA-7. Every plan inside is metered; the module is off by default.
# ---------------------------------------------------------------------------
module "defender" {
  count  = var.enable_defender_for_cloud && var.enable_logging ? 1 : 0
  source = "./modules/defender"

  name_prefix         = var.name_prefix
  resource_group_name = azurerm_resource_group.compliance.name
  location            = var.primary_location
  subscription_id     = var.subscription_id

  fedramp_baseline = var.fedramp_baseline

  # Baseline-driven: P2 adds the agent-based vulnerability assessment and file
  # integrity monitoring that RA-5 and SI-7 expect at the High baseline.
  servers_subplan          = local.baseline.defender_servers_subplan
  storage_malware_scanning = local.baseline.defender_storage_malware_scanning

  log_analytics_workspace_id = one(module.logging[*].workspace_id)

  enable_servers        = var.enable_defender_servers
  enable_storage        = var.enable_defender_storage
  enable_sql            = var.enable_defender_sql
  enable_containers     = var.enable_defender_containers
  enable_key_vault      = var.enable_defender_key_vault
  enable_arm            = var.enable_defender_arm
  enable_app_services   = var.enable_defender_app_services
  enable_open_source_db = var.enable_defender_open_source_db

  enable_continuous_export = var.enable_defender_continuous_export
  enable_auto_provisioning = var.enable_defender_auto_provisioning

  security_contact_emails = var.security_contact_emails
  security_contact_phone  = var.security_contact_phone

  event_hub_resource_id       = var.event_hub_resource_id
  event_hub_connection_string = var.event_hub_connection_string

  tags = local.tags
}

# ---------------------------------------------------------------------------
# SC-5 / SC-7 / AU-12 at the network layer.
# ---------------------------------------------------------------------------
module "network" {
  count  = var.enable_network ? 1 : 0
  source = "./modules/network"

  name_prefix         = var.name_prefix
  unique_suffix       = local.unique
  resource_group_name = azurerm_resource_group.compliance.name
  location            = var.primary_location
  subscription_id     = var.subscription_id
  azure_environment   = var.azure_environment

  deny_internet_egress    = var.deny_internet_egress
  flow_log_retention_days = var.flow_log_retention_days

  enable_network_watcher   = var.enable_network_watcher
  enable_nsg_flow_logs     = var.enable_nsg_flow_logs
  enable_ddos_protection   = var.enable_ddos_protection
  enable_private_endpoints = var.enable_private_endpoints

  log_analytics_workspace_id   = one(module.logging[*].workspace_id)
  log_analytics_workspace_guid = one(module.logging[*].workspace_customer_id)

  key_vault_id               = one(module.encryption[*].key_vault_id)
  archive_storage_account_id = one(module.logging[*].archive_storage_account_id)

  tags = local.tags
}

# ---------------------------------------------------------------------------
# AC-2 / AU-6: read-only access for assessors and the SOC.
#
# Assessors need to see the estate without being able to change it. Handing out
# subscription Reader is the usual shortcut and it grants read on data-plane
# resources too. Security Reader is the narrower role that still shows Defender
# findings, policy compliance state and secure score -- which is the entire
# evidence surface -- and nothing else.
#
# Entra ID Conditional Access, PIM eligibility and access review scheduling for
# these principals are deliberately out of scope for this repo. See the README.
# ---------------------------------------------------------------------------
resource "azurerm_role_assignment" "assessor_security_reader" {
  for_each = toset(var.assessor_principal_ids)

  scope              = local.policy_scope_id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/39bc4728-0917-49c7-9d2c-d95423bc2eb4"
  principal_id       = each.value

  description = "AC-2 / CA-2: read-only evidence access for assessors. Security Reader, not Reader -- it exposes findings and compliance state without data-plane read."
}
