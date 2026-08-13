# ---------------------------------------------------------------------------
# Continuous export.
#
# The Defender for Cloud portal keeps findings for a rolling window and its API
# is not a long-term evidence store. AU-11 (audit record retention) and CA-7
# (continuous monitoring with defined metrics over time) both need the findings
# to persist beyond that window, and an assessor asking "show me the secure score
# trend for the last six months" needs a table to query, not a screenshot.
#
# Two sinks, deliberately:
#   Log Analytics -- joinable against the Activity Log and resource diagnostics
#                    for hunting (AU-6(3)).
#   Event Hub     -- egress to a SIEM the subscription owner does not administer,
#                    which is the AU-9(2) "store on a separate system" argument.
# ---------------------------------------------------------------------------

locals {
  # Sub-assessments carry the per-resource detail (which CVE, which setting);
  # assessments alone are the roll-up and are not sufficient evidence.
  export_event_sources = [
    "Alerts",
    "Assessments",
    "SubAssessments",
    "SecureScores",
    "SecureScoreControls",
    "RegulatoryComplianceAssessment",
  ]
}

resource "azurerm_security_center_automation" "to_log_analytics" {
  count = var.enable_continuous_export ? 1 : 0

  name                = "export-${var.name_prefix}-to-law"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${var.subscription_id}"]
  description         = "AU-6(3) / CA-7: Defender findings land in the same workspace as the Activity Log so correlation queries can join them."
  enabled             = true

  action {
    type        = "LogAnalytics"
    resource_id = var.log_analytics_workspace_id
  }

  dynamic "source" {
    for_each = toset(local.export_event_sources)
    content {
      event_source = source.value
    }
  }

  tags = var.tags
}

resource "azurerm_security_center_automation" "to_event_hub" {
  count = var.enable_continuous_export && var.event_hub_resource_id != null && var.event_hub_connection_string != null ? 1 : 0

  name                = "export-${var.name_prefix}-to-eventhub"
  location            = var.location
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${var.subscription_id}"]
  description         = "AU-9(2): findings copied to a SIEM outside this subscription's administrative control, so compromising the subscription does not erase the evidence."
  enabled             = true

  action {
    type              = "EventHub"
    resource_id       = var.event_hub_resource_id
    connection_string = var.event_hub_connection_string
  }

  dynamic "source" {
    for_each = toset(local.export_event_sources)
    content {
      event_source = source.value
    }
  }

  tags = var.tags
}
