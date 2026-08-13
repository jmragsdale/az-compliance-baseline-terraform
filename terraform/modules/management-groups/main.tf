# ---------------------------------------------------------------------------
# Management group hierarchy.
#
# Why this exists as a *control* and not just as tidy housekeeping:
#
#   AC-3 / AC-6   Least privilege is unenforceable without a scope boundary to
#                 attach it to. RBAC and Azure Policy both inherit down the MG
#                 tree, so the tree is the enforcement topology.
#   CM-2 / CM-6   A baseline configuration has to apply to a defined set of
#                 systems. The MG tree is how "the set of systems in the FedRAMP
#                 boundary" is expressed in Azure.
#   SC-7          Separating prod from nonprod from sandbox at MG level lets
#                 boundary policy (allowed regions, public IP denial) differ by
#                 environment without per-subscription drift.
#   CIS Azure v3.0.0 section 1 expects a deliberate MG structure rather than a
#                 flat tenant with every subscription under the root group.
#
# Deliberate choice: this module creates an *intermediate* root and never writes
# to the tenant root group. Policy at the tenant root applies to every future
# subscription including the ones the platform team does not own yet, and it
# cannot be scoped away. That is a one-way door and it is not one this module
# opens on your behalf.
# ---------------------------------------------------------------------------

resource "azurerm_management_group" "root" {
  name                       = "mg-${var.name_prefix}-root"
  display_name               = var.root_display_name
  parent_management_group_id = var.parent_management_group_id
}

# --- Platform: shared services the whole estate depends on ------------------
# Logging, keys, connectivity and identity plumbing live here. Separated from
# workloads so that CM-5 (access restrictions for change) can be enforced with a
# different set of RBAC assignments than the landing zones get.
resource "azurerm_management_group" "platform" {
  name                       = "mg-${var.name_prefix}-platform"
  display_name               = "Platform"
  parent_management_group_id = azurerm_management_group.root.id
}

# --- Landing zones: where workloads actually run ----------------------------
resource "azurerm_management_group" "landing_zones" {
  name                       = "mg-${var.name_prefix}-landing-zones"
  display_name               = "Landing Zones"
  parent_management_group_id = azurerm_management_group.root.id
}

# SC-7 / CM-2: production carries the full deny set. Non-production carries the
# same detective controls but a relaxed preventive set so that engineering can
# still move; the split is what makes the strict prod posture politically viable.
resource "azurerm_management_group" "prod" {
  name                       = "mg-${var.name_prefix}-prod"
  display_name               = "Landing Zones - Production"
  parent_management_group_id = azurerm_management_group.landing_zones.id
}

resource "azurerm_management_group" "nonprod" {
  name                       = "mg-${var.name_prefix}-nonprod"
  display_name               = "Landing Zones - Non-Production"
  parent_management_group_id = azurerm_management_group.landing_zones.id
}

# --- Sandbox: explicitly outside the authorization boundary -----------------
# CA-3 / SA-9: sandbox subscriptions are declared out of boundary. Naming them
# and isolating them is what lets an assessor accept "not in scope" as an answer
# instead of treating every subscription in the tenant as in scope.
resource "azurerm_management_group" "sandbox" {
  name                       = "mg-${var.name_prefix}-sandbox"
  display_name               = "Sandbox (outside the authorization boundary)"
  parent_management_group_id = azurerm_management_group.root.id
}

# --- Decommissioned: the graveyard -----------------------------------------
# MP-6 / SR-12: subscriptions pending media sanitisation and deletion land here.
# Keeping them in the tree rather than deleting them immediately preserves the
# audit trail through the disposal process.
resource "azurerm_management_group" "decommissioned" {
  name                       = "mg-${var.name_prefix}-decommissioned"
  display_name               = "Decommissioned"
  parent_management_group_id = azurerm_management_group.root.id
}

# ---------------------------------------------------------------------------
# Subscription placement.
#
# Modelled as a separate association resource rather than the (deprecated)
# `subscription_ids` argument on azurerm_management_group, because that argument
# is authoritative: it silently evicts any subscription Terraform does not know
# about. Association resources are additive and safe to run against a tenant
# that has subscriptions managed elsewhere.
# ---------------------------------------------------------------------------

locals {
  target_ids = {
    platform       = azurerm_management_group.platform.id
    prod           = azurerm_management_group.prod.id
    nonprod        = azurerm_management_group.nonprod.id
    sandbox        = azurerm_management_group.sandbox.id
    decommissioned = azurerm_management_group.decommissioned.id
  }

  # Flatten map(list) -> map of "key/subscription" -> {mg, sub} for for_each.
  associations = merge([
    for mg_key, subs in var.subscription_associations : {
      for sub in subs : "${mg_key}/${sub}" => {
        management_group_id = local.target_ids[mg_key]
        subscription_id     = "/subscriptions/${sub}"
      }
    }
  ]...)
}

resource "azurerm_management_group_subscription_association" "this" {
  for_each = local.associations

  management_group_id = each.value.management_group_id
  subscription_id     = each.value.subscription_id
}
