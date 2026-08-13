# ---------------------------------------------------------------------------
# Built-in regulatory compliance initiatives.
#
# Microsoft maintains policy set definitions that encode the technical portions of
# FedRAMP, NIST 800-53 and CIS. Assigning them is what makes the Defender for Cloud
# "Regulatory compliance" dashboard light up with the right framework, and that
# dashboard is the artifact assessors actually ask to see. Re-implementing those
# hundreds of individual policies by hand would be worse in every dimension:
# it would drift the moment Microsoft revises the mapping.
#
# CA-2 (assessments), CA-7 (continuous monitoring) and PM-31 are the controls this
# satisfies: continuous, automated evaluation of the boundary against a named
# baseline, with per-control evidence.
#
# ---------------------------------------------------------------------------
# ABOUT THESE GUIDS -- READ BEFORE APPLYING
# ---------------------------------------------------------------------------
# Built-in policy set definition IDs are stable GUIDs, but they are NOT
# discoverable from documentation reliably enough to hard-code blind, and they
# differ in some sovereign clouds. Entries below carry an explicit `verified`
# flag. Anything with verified = false is NOT assigned unless you either:
#
#   (a) pass the real GUID via var.builtin_initiative_id_overrides, or
#   (b) consciously set var.trust_unverified_initiative_ids = true
#
# Get the real values from the tenant you are targeting:
#
#   az policy set-definition list --query \
#     "[?policyType=='BuiltIn'].{name:name, display:displayName}" -o table \
#     | grep -i -e fedramp -e 'NIST SP 800-53' -e CIS -e 'Cloud Security Benchmark'
#
# Or for one initiative:
#
#   az policy set-definition list \
#     --query "[?displayName=='FedRAMP High'].name" -o tsv
#
# The repo will tell you what it skipped: see the
# `initiatives_requiring_verification` output.
# ---------------------------------------------------------------------------

locals {
  builtin_initiatives = {
    # ---- FedRAMP Rev 4/5 baselines -------------------------------------
    # Microsoft publishes these two as "FedRAMP Moderate" and "FedRAMP High".
    # These GUIDs are the long-standing public commercial-cloud values.
    fedramp_moderate = {
      display_name = "FedRAMP Moderate"
      id           = "e95f5a9f-57ad-4d03-bb0b-b1d16db93693"
      verified     = true
      note         = "Commercial cloud built-in. Azure Government publishes the same displayName; confirm the GUID in your cloud."
    }

    fedramp_high = {
      display_name = "FedRAMP High"
      id           = "d5264498-16f4-418a-b659-fa7ef418175f"
      verified     = true
      note         = "Commercial cloud built-in. Confirm in Azure Government before apply."
    }

    # ---- NIST SP 800-53 Rev 5 ------------------------------------------
    nist_800_53_r5 = {
      display_name = "NIST SP 800-53 Rev. 5"
      id           = "179d1daa-458f-4e47-8086-2a68d0d6c38f"
      verified     = true
      note         = "Rev 4 is a different initiative (cf25b9c1-bd23-4eb6-bd2c-f4f3ac644a5f); do not confuse them."
    }

    # ---- Microsoft Cloud Security Benchmark ----------------------------
    # Assigned to every subscription by default under the name "ASC Default" in
    # older tenants. Re-assigning it at MG scope makes it explicit and versioned.
    mcsb = {
      display_name = "Microsoft cloud security benchmark"
      id           = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
      verified     = true
      note         = "Formerly 'Azure Security Benchmark'. Often already assigned as ASC Default at subscription scope."
    }

    # ---- CIS Microsoft Azure Foundations Benchmark ---------------------
    # v3.0.0 is the version this repo claims coverage against. I do not have a
    # GUID for it that I am willing to hard-code, and guessing one would silently
    # assign the wrong benchmark version -- which is worse than assigning none,
    # because the dashboard would look green against the wrong control set.
    cis_azure_v3_0_0 = {
      display_name = "CIS Microsoft Azure Foundations Benchmark v3.0.0"
      id           = null
      verified     = false
      note         = "UNVERIFIED: supply via builtin_initiative_id_overrides. Find it with: az policy set-definition list --query \"[?contains(displayName,'CIS Microsoft Azure Foundations Benchmark v3')].name\" -o tsv"
    }

    # v2.0.0 shipped as a candidate fallback for tenants that have not picked up
    # the v3 built-in yet. Still gated behind the trust flag -- see header.
    cis_azure_v2_0_0 = {
      display_name = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
      id           = "06f19060-9e68-4070-92ca-f15cc126059e"
      verified     = false
      note         = "CANDIDATE GUID, not verified by this repo. Only assigned with trust_unverified_initiative_ids = true or an explicit override."
    }
  }

  # Which initiatives this deployment wants, given the selected baseline. Only one
  # of the two FedRAMP initiatives is ever assigned: assigning both produces
  # duplicated, conflicting DINE remediations and a compliance dashboard that
  # double-counts every finding.
  requested_initiative_keys = [
    var.primary_initiative_key,
    "nist_800_53_r5",
    "mcsb",
    "cis_azure_v3_0_0",
    "cis_azure_v2_0_0",
  ]

  # Resolve each requested key to an effective GUID, honouring overrides first.
  resolved_initiative_ids = {
    for k in local.requested_initiative_keys : k => (
      try(var.builtin_initiative_id_overrides[k], null) != null
      ? var.builtin_initiative_id_overrides[k]
      : (
        (local.builtin_initiatives[k].verified || var.trust_unverified_initiative_ids)
        ? local.builtin_initiatives[k].id
        : null
      )
    )
  }

  assignable_initiatives = {
    for k, id in local.resolved_initiative_ids : k => {
      id            = "/providers/Microsoft.Authorization/policySetDefinitions/${id}"
      display_name  = local.builtin_initiatives[k].display_name
      assignment_id = substr("${var.name_prefix}-${replace(k, "_", "-")}", 0, 24)
    } if id != null
  }

  skipped_initiatives = {
    for k, id in local.resolved_initiative_ids : k => local.builtin_initiatives[k].note
    if id == null
  }

  mg_scope = var.deployment_scope == "management_group"

  regulatory_mg  = (local.mg_scope && var.enable_regulatory_initiatives) ? local.assignable_initiatives : {}
  regulatory_sub = (!local.mg_scope && var.enable_regulatory_initiatives) ? local.assignable_initiatives : {}
}

# ---------------------------------------------------------------------------
# Assignments at management group scope.
#
# `identity` is present because these initiatives contain deployIfNotExists and
# modify policies (diagnostic settings, agent deployment, TLS enforcement). Without
# a remediation identity those policies evaluate but can never remediate, which
# turns a preventive control into a permanently red dashboard row.
# ---------------------------------------------------------------------------
resource "azurerm_management_group_policy_assignment" "regulatory" {
  for_each = local.regulatory_mg

  name                 = each.value.assignment_id
  display_name         = "${each.value.display_name} (baseline: ${var.fedramp_baseline})"
  description          = "Continuous evaluation of the authorization boundary against ${each.value.display_name}. Satisfies CA-7 continuous monitoring; produces the per-control evidence CA-2 assessments consume."
  policy_definition_id = each.value.id
  management_group_id  = var.management_group_id
  enforce              = var.enforcement_mode == "Default"
  location             = var.location

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }

  non_compliance_message {
    content = "Resource violates the ${each.value.display_name} baseline enforced by az-compliance-baseline-terraform. See CONTROLS.md for the mapping and the exemption process."
  }

  depends_on = [
    azurerm_role_assignment.remediation_contributor_mg,
    azurerm_role_assignment.remediation_security_admin_mg,
  ]
}

resource "azurerm_subscription_policy_assignment" "regulatory" {
  for_each = local.regulatory_sub

  name                 = each.value.assignment_id
  display_name         = "${each.value.display_name} (baseline: ${var.fedramp_baseline})"
  description          = "Continuous evaluation of this subscription against ${each.value.display_name}. CA-7 continuous monitoring."
  policy_definition_id = each.value.id
  subscription_id      = "/subscriptions/${var.subscription_id}"
  enforce              = var.enforcement_mode == "Default"
  location             = var.location

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }

  non_compliance_message {
    content = "Resource violates the ${each.value.display_name} baseline enforced by az-compliance-baseline-terraform."
  }

  depends_on = [
    azurerm_role_assignment.remediation_contributor_sub,
    azurerm_role_assignment.remediation_security_admin_sub,
  ]
}
