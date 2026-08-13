# ---------------------------------------------------------------------------
# Microsoft Defender for Cloud.
#
# This module is the detective half of the baseline. Policy stops the bad
# configuration from being created; Defender notices the ones that predate the
# policy, the ones an exemption allows, and the runtime behaviour policy cannot
# see at all.
#
# Framework mapping, honestly stated:
#   RA-5   vulnerability monitoring -- Defender for Servers P2 supplies the
#          agent-based VA that RA-5 wants; P1 supplies agentless posture only.
#   SI-4   system monitoring -- the alert pipeline.
#   SI-3   malicious code protection -- Defender for Storage malware scanning.
#   SI-7   software/firmware integrity -- file integrity monitoring (P2 only).
#   CA-7   continuous monitoring -- the regulatory compliance dashboard.
#   IR-6   incident reporting -- security contacts.
#   AU-6(3) audit correlation -- continuous export into the same workspace the
#          Activity Log lands in, so hunting queries can join them.
#
# EVERY plan below is metered per resource per month and every one defaults to
# off. Turning them all on across a large estate is a four-to-five figure monthly
# bill. See the Cost section of the README before flipping switches.
# ---------------------------------------------------------------------------

locals {
  # resource_type -> plan configuration. Kept uniform so the map type unifies.
  all_plans = {
    VirtualMachines = {
      enabled = var.enable_servers
      tier    = "Standard"
      subplan = var.servers_subplan
    }
    StorageAccounts = {
      enabled = var.enable_storage
      tier    = "Standard"
      # V2 is the per-storage-account plan; the older per-transaction plan is
      # deprecated and prices very differently.
      subplan = "DefenderForStorageV2"
    }
    SqlServers = {
      enabled = var.enable_sql
      tier    = "Standard"
      subplan = null
    }
    SqlServerVirtualMachines = {
      enabled = var.enable_sql
      tier    = "Standard"
      subplan = null
    }
    Containers = {
      enabled = var.enable_containers
      tier    = "Standard"
      subplan = null
    }
    KeyVaults = {
      enabled = var.enable_key_vault
      tier    = "Standard"
      subplan = null
    }
    Arm = {
      enabled = var.enable_arm
      tier    = "Standard"
      # The PerApiCall sub-plan was retired; Arm is a flat per-subscription plan
      # now. Passing a sub-plan here produces an API error, not a warning.
      subplan = null
    }
    AppServices = {
      enabled = var.enable_app_services
      tier    = "Standard"
      subplan = null
    }
    OpenSourceRelationalDatabases = {
      enabled = var.enable_open_source_db
      tier    = "Standard"
      subplan = null
    }
  }

  enabled_plans = { for k, v in local.all_plans : k => v if v.enabled }

  # SI-3: malware scanning and sensitive-data discovery are separately metered
  # extensions on the Storage plan. High baseline turns them on; Moderate does
  # not, because the per-GB scanning charge on a high-throughput data lake is
  # substantial and RA-2 lets you make that call based on data classification.
  storage_extensions = var.storage_malware_scanning ? [
    {
      name       = "OnUploadMalwareScanning"
      properties = { "CapGBPerMonthPerStorageAccount" = "5000" }
    },
    {
      name       = "SensitiveDataDiscovery"
      properties = {}
    },
  ] : []

  plan_extensions = {
    StorageAccounts = local.storage_extensions
  }
}

resource "azurerm_security_center_subscription_pricing" "this" {
  #checkov:skip=CKV_AZURE_19:Tier is "Standard" for every entry in local.all_plans; Checkov cannot resolve it through the for_each map. The tier is the *reason* these resources exist -- a Free-tier pricing resource would be a no-op.
  for_each = local.enabled_plans

  resource_type = each.key
  tier          = each.value.tier
  subplan       = each.value.subplan

  dynamic "extension" {
    for_each = { for e in lookup(local.plan_extensions, each.key, []) : e.name => e }
    content {
      name                            = extension.value.name
      additional_extension_properties = extension.value.properties
    }
  }
}

# ---------------------------------------------------------------------------
# IR-6 incident reporting.
#
# An alert that nobody is paged for is a log entry. Defender notifies the
# security contact on high-severity alerts and on attack paths; this is the only
# place in the product where that routing is configured.
# ---------------------------------------------------------------------------
resource "azurerm_security_center_contact" "this" {
  count = length(var.security_contact_emails) > 0 ? 1 : 0

  name  = "default"
  email = join(";", var.security_contact_emails)
  phone = var.security_contact_phone

  alert_notifications = true

  # Subscription Owners are notified in addition to the named contacts. Owners
  # are the people who can actually act on a compromised subscription.
  alerts_to_admins = true
}

# ---------------------------------------------------------------------------
# Where Defender's own findings land.
#
# AU-6(3) audit record correlation: Defender alerts have to sit in the same
# workspace as the Activity Log and resource diagnostics, or the hunting query
# that ties "suspicious sign-in" to "role assignment created" to "storage account
# firewall opened" cannot be written at all.
# ---------------------------------------------------------------------------
resource "azurerm_security_center_workspace" "this" {
  scope        = "/subscriptions/${var.subscription_id}"
  workspace_id = var.log_analytics_workspace_id
}

# SI-4: Defender for Servers is only as good as its telemetry. Without an agent
# on the VM there is no process telemetry, no file integrity monitoring and no
# vulnerability assessment -- just agentless disk scanning.
#
# NOTE: Microsoft has retired Log Analytics agent auto-provisioning in favour of
# the Azure Monitor Agent delivered by policy. This resource covers the legacy
# setting; the AMA rollout is handled by the DINE initiative in the logging
# module. Both exist because tenants are mid-migration for a long time.
# Deprecated in azurerm v4 and removed in v5: Microsoft is retiring the Log
# Analytics agent auto-provisioning path in favour of agentless scanning and
# the Azure Monitor Agent. Kept while the provider is pinned ~> 4.0 because
# it is still the only Terraform surface for the setting; the migration is
# tracked in DEVLOG.md rather than silently deferred.
resource "azurerm_security_center_auto_provisioning" "this" {
  auto_provision = var.enable_auto_provisioning ? "On" : "Off"
}

# ---------------------------------------------------------------------------
# Integrations. Each is a data-sharing decision, so each is explicit rather than
# left at whatever the subscription defaulted to years ago.
# ---------------------------------------------------------------------------
resource "azurerm_security_center_setting" "mcas" {
  setting_name = "MCAS"
  enabled      = var.enable_servers
}

resource "azurerm_security_center_setting" "wdatp" {
  setting_name = "WDATP"
  enabled      = var.enable_servers
}

# ---------------------------------------------------------------------------
# A note on "regulatory compliance standards assignment".
#
# In Defender for Cloud, a regulatory standard (FedRAMP High, NIST 800-53 Rev 5,
# CIS Azure Foundations) IS a policy initiative assignment. There is no separate
# object to create: assigning the built-in initiative at MG or subscription scope
# is what makes the standard appear on the Regulatory Compliance dashboard.
#
# That assignment lives in the policy module (modules/policy/initiatives.tf) so
# that scope gating and the remediation identity are handled in one place. This
# comment exists because "where do I assign the standard" is the single most
# common point of confusion in Defender, and the answer is "you already did".
#
# What this module adds on top is a custom assessment for a control Microsoft
# does not ship an assessment for: whether the audit archive's immutability
# policy has actually been locked.
# ---------------------------------------------------------------------------
resource "azurerm_security_center_assessment_policy" "worm_lock" {
  display_name = "Audit archive immutability policy must be Locked"
  severity     = "High"
  description  = "AU-9(3): a time-based retention policy in Unlocked state can be shortened or removed by a subscription owner, which defeats the purpose of WORM. Locking is irreversible and must be done deliberately after the retention period is confirmed correct."
  categories   = ["Data"]

  remediation_description = "Confirm the retention period matches the AU-11 requirement for this baseline, then lock it: az storage account immutability-policy update --account-name <acct> --resource-group <rg> --state Locked. This cannot be undone."
}
