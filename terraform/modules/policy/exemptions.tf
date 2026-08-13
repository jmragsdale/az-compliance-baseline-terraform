# ---------------------------------------------------------------------------
# The exemption pattern.
#
# Exemptions are the part of a policy baseline that decides whether people work
# with it or around it. Without a supported way to say "not this resource, and
# here is why", teams delete the assignment, weaken the effect to Audit, or run
# outside the boundary entirely -- all of which are worse than a tracked,
# expiring exemption.
#
# The schema in var.exemptions forces three things an assessor will demand:
#   1. a justification string that ends up in the resource description and is
#      readable from `az policy exemption list` (CA-5 plan of action)
#   2. an expiry date -- Azure stops honouring the exemption automatically, so
#      an unrenewed waiver fails closed rather than lasting forever (CA-5, CM-3)
#   3. a category, Waiver vs Mitigated, which is the difference between "we
#      accept this risk" and "we handle it another way" (RA-3 risk assessment)
#
# Exemptions naming an assignment key that does not exist in this deployment are
# dropped rather than erroring, so that a shared tfvars file can carry exemptions
# for initiatives a given environment does not assign.
# ---------------------------------------------------------------------------

locals {
  assignment_ids = merge(
    { for k, v in azurerm_management_group_policy_assignment.regulatory : k => v.id },
    { for k, v in azurerm_subscription_policy_assignment.regulatory : k => v.id },
    length(azurerm_management_group_policy_assignment.custom_guardrails) > 0
    ? { guardrails = azurerm_management_group_policy_assignment.custom_guardrails[0].id } : {},
    length(azurerm_subscription_policy_assignment.custom_guardrails) > 0
    ? { guardrails = azurerm_subscription_policy_assignment.custom_guardrails[0].id } : {},
  )

  resolvable_exemptions = {
    for k, v in var.exemptions : k => v
    if contains(keys(local.assignment_ids), v.policy_assignment_key)
  }

  dropped_exemptions = [
    for k, v in var.exemptions : "${k} -> ${v.policy_assignment_key}"
    if !contains(keys(local.assignment_ids), v.policy_assignment_key)
  ]

  mg_exemptions = {
    for k, v in local.resolvable_exemptions : k => v
    if length(regexall("/providers/Microsoft.Management/managementGroups/", v.scope_id)) > 0
  }

  sub_exemptions = {
    for k, v in local.resolvable_exemptions : k => v
    if length(regexall("^/subscriptions/[^/]+$", v.scope_id)) > 0
  }

  resource_exemptions = {
    for k, v in local.resolvable_exemptions : k => v
    if length(regexall("/providers/Microsoft.Management/managementGroups/", v.scope_id)) == 0
    && length(regexall("^/subscriptions/[^/]+$", v.scope_id)) == 0
  }

  exemption_description = {
    for k, v in local.resolvable_exemptions : k =>
    "[${v.category}] ${v.justification} | expires ${v.expires_on} | tracked by az-compliance-baseline-terraform"
  }
}

resource "azurerm_management_group_policy_exemption" "this" {
  for_each = local.mg_exemptions

  name                            = "exmp-${each.key}"
  display_name                    = "Exemption: ${each.key}"
  description                     = local.exemption_description[each.key]
  management_group_id             = each.value.scope_id
  policy_assignment_id            = local.assignment_ids[each.value.policy_assignment_key]
  exemption_category              = each.value.category
  expires_on                      = each.value.expires_on
  policy_definition_reference_ids = each.value.policy_definition_reference_ids
}

resource "azurerm_subscription_policy_exemption" "this" {
  for_each = local.sub_exemptions

  name                            = "exmp-${each.key}"
  display_name                    = "Exemption: ${each.key}"
  description                     = local.exemption_description[each.key]
  subscription_id                 = each.value.scope_id
  policy_assignment_id            = local.assignment_ids[each.value.policy_assignment_key]
  exemption_category              = each.value.category
  expires_on                      = each.value.expires_on
  policy_definition_reference_ids = each.value.policy_definition_reference_ids
}

resource "azurerm_resource_policy_exemption" "this" {
  for_each = local.resource_exemptions

  name                            = "exmp-${each.key}"
  display_name                    = "Exemption: ${each.key}"
  description                     = local.exemption_description[each.key]
  resource_id                     = each.value.scope_id
  policy_assignment_id            = local.assignment_ids[each.value.policy_assignment_key]
  exemption_category              = each.value.category
  expires_on                      = each.value.expires_on
  policy_definition_reference_ids = each.value.policy_definition_reference_ids
}
