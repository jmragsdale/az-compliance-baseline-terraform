# ---------------------------------------------------------------------------
# The baseline matrix.
#
# FedRAMP Rev 5 Moderate and High share the same control *set* almost entirely --
# what changes is the parameterisation. Rather than fork the code, every value that
# differs between the two baselines lives here and is selected by one lookup. That
# keeps the two baselines from drifting apart, which is the failure mode of the
# "copy the module and edit it" approach.
#
# Sources for the deltas:
#   AU-11  audit record retention   -- Moderate: 90d online + 1yr; High: 1yr online + longer archive
#   SC-12/SC-13 key management      -- High wants shorter crypto periods and larger keys
#   RA-5   vulnerability scanning   -- High wants agent-based VA + file integrity monitoring
#   CP-9   backup / CP-10 recovery  -- High wants geo-redundant, read-accessible copies
# ---------------------------------------------------------------------------

locals {
  baseline_matrix = {
    moderate = {
      # Built-in regulatory initiative that defines "compliant" for this baseline.
      primary_initiative_key = "fedramp_moderate"

      # AU-11: online searchable retention, then WORM archive.
      log_retention_days     = 365
      archive_immutable_days = 1095 # 3 years

      # CP-9 / CP-10: geo-redundancy of the audit archive.
      archive_replication = "GRS"

      # SC-12(1) / SC-13: key strength and cryptographic period.
      key_size            = 3072
      key_rotation_period = "P365D"
      key_expiry_period   = "P730D"
      key_notify_before   = "P30D"

      # RA-5 / SI-7: Defender for Servers plan. P1 is agentless posture only.
      defender_servers_subplan = "P1"

      # Defender for Storage sub-plan; malware scanning is a High-baseline expectation.
      defender_storage_malware_scanning = false

      # AC-2(3): how long before an unremediated finding is escalated.
      assessment_grace_period_days = 30

      # SI-4: soft-delete windows on blob data supporting audit archive.
      blob_soft_delete_days = 30
    }

    high = {
      primary_initiative_key = "fedramp_high"

      log_retention_days     = 730
      archive_immutable_days = 2555 # 7 years

      archive_replication = "RAGRS"

      key_size            = 4096
      key_rotation_period = "P180D"
      key_expiry_period   = "P365D"
      key_notify_before   = "P30D"

      defender_servers_subplan = "P2"

      defender_storage_malware_scanning = true

      assessment_grace_period_days = 7

      blob_soft_delete_days = 90
    }
  }

  baseline = local.baseline_matrix[var.fedramp_baseline]

  # -------------------------------------------------------------------------
  # Scope gating. Every Microsoft.Management resource is behind this so that
  # single_subscription mode plans without tenant-root-scope RBAC.
  # -------------------------------------------------------------------------
  mg_scope = var.deployment_scope == "management_group"

  # -------------------------------------------------------------------------
  # Naming. Deterministic (hashed from inputs, not random) so that a re-plan
  # from a clean state file does not propose renaming every resource.
  # -------------------------------------------------------------------------
  unique = substr(sha1(join("|", [var.name_prefix, var.subscription_id, var.primary_location])), 0, 6)

  resource_group_name = "rg-${var.name_prefix}-compliance-${var.primary_location}"

  # CM-8: tags are the inventory. Without them an assessor cannot answer
  # "show me every resource in the authorization boundary" from the portal.
  tags = merge(
    {
      "managed-by"          = "terraform"
      "terraform-module"    = "az-compliance-baseline-terraform"
      "compliance-baseline" = "fedramp-${var.fedramp_baseline}"
      "deployment-scope"    = var.deployment_scope
      "system-id"           = var.system_id
    },
    var.tags,
  )

  # -------------------------------------------------------------------------
  # Effective scope handed to the policy module. In MG mode this is the
  # intermediate root MG; in single-subscription mode it is the subscription.
  # -------------------------------------------------------------------------
  subscription_resource_id = "/subscriptions/${var.subscription_id}"

  policy_scope_id = local.mg_scope ? one(module.management_groups[*].root_management_group_id) : local.subscription_resource_id
}
