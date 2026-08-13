# ---------------------------------------------------------------------------
# Central audit record store.
#
# AU-2 (event logging), AU-3 (content), AU-4 (storage capacity), AU-6 (review and
# analysis), AU-9 (protection of audit information) and AU-11 (retention) all
# collapse to one architectural requirement in Azure: a single workspace that
# every subscription in the boundary writes to, that workload owners cannot
# delete or edit, and that keeps records long enough to investigate an incident
# discovered late.
#
# Retention is baseline-driven: 365 days interactive for Moderate, 730 for High,
# with the WORM archive carrying the multi-year tail (AU-11 does not care where
# the record lives, only that it is retrievable and unaltered).
# ---------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "core" {
  name                = "log-${var.name_prefix}-core-${var.location}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"

  # AU-11 retention window, selected by fedramp_baseline.
  retention_in_days = var.log_retention_days

  # AU-4 / AU-5: capping ingestion protects the bill but *drops* audit records
  # once the cap is hit. That is a deliberate availability-vs-completeness call,
  # which is why it is uncapped (-1) unless a caller opts in.
  daily_quota_gb = var.daily_quota_gb

  # AU-9: keep the workspace reachable from Azure services but treat query access
  # as an RBAC decision rather than a network one; the workspace is not a public
  # data store either way.
  internet_ingestion_enabled = true
  internet_query_enabled     = true

  # IA-2 / AC-3: Entra ID authentication only. The workspace shared keys are
  # bearer credentials with full ingest rights that no directory sees and that no
  # access review can find. Note that some legacy agents authenticate with the
  # workspace key and will fail to enrol once this is set -- the Azure Monitor
  # Agent (delivered by the DINE initiative in dine.tf) uses managed identity and
  # is unaffected.
  local_authentication_disabled = true

  tags = merge(var.tags, {
    "control-family" = "AU"
    "retention-days" = tostring(var.log_retention_days)
  })
}

# ---------------------------------------------------------------------------
# Subscription Activity Log.
#
# This is the control-plane audit trail: every ARM write, every role assignment,
# every policy change, every Defender configuration change. AU-2 requires it,
# AU-6 requires it to be reviewable, and CIS Microsoft Azure Foundations v3.0.0
# section 5 requires a diagnostic setting that captures Administrative, Security,
# Policy and Alert categories specifically.
#
# The Activity Log is retained for 90 days by the platform whether or not you
# configure this. 90 days is shorter than the dwell time of most real intrusions,
# which is the entire reason this resource exists.
# ---------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "diag-${var.name_prefix}-activity-to-law"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.core.id

  # CIS Azure v3.0.0 5.x enumerates these categories explicitly. Administrative
  # and Policy are the two that matter for detecting an attacker weakening the
  # baseline itself.
  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "ServiceHealth" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Recommendation" }
  enabled_log { category = "Policy" }
  enabled_log { category = "Autoscale" }
  enabled_log { category = "ResourceHealth" }
}

# AU-9(2): a copy of the audit record on a system the subscription owner does not
# administer. Streaming to an Event Hub the SIEM owns means compromising the
# subscription does not let you erase your own tracks in the SIEM.
resource "azurerm_monitor_diagnostic_setting" "activity_log_eventhub" {
  count = var.enable_event_hub_export ? 1 : 0

  name                           = "diag-${var.name_prefix}-activity-to-eventhub"
  target_resource_id             = "/subscriptions/${var.subscription_id}"
  eventhub_authorization_rule_id = var.event_hub_authorization_rule_id
  eventhub_name                  = var.event_hub_name

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Policy" }
  enabled_log { category = "Alert" }
}

# ---------------------------------------------------------------------------
# Key Vault audit events.
#
# AU-2 and CIS Microsoft Azure Foundations v3.0.0 8.5. This is the highest-signal
# log source in the tenant: an attacker who has reached the CMK has reached
# everything the CMK protects, and AuditEvent is where that first shows up.
#
# It lives in the logging module rather than the encryption module on purpose --
# routing it from encryption would make the encryption module depend on the
# logging module while logging already depends on encryption for the CMK, and
# Terraform will not resolve that.
# ---------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  count = var.key_vault_id != null ? 1 : 0

  name                       = "diag-${var.name_prefix}-keyvault"
  target_resource_id         = var.key_vault_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.core.id

  enabled_log { category = "AuditEvent" }
  enabled_log { category = "AzurePolicyEvaluationDetails" }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
