# ---------------------------------------------------------------------------
# Control-plane change alerting.
#
# AU-6(1) requires automated review of audit records, and SI-4(5) requires an
# alert when indications of compromise appear. Collecting the Activity Log
# satisfies AU-2; nobody reads it. These alerts fire on the specific operations
# an attacker performs to make themselves persistent or invisible:
#
#   - weakening or deleting a policy assignment (removes the guardrails)
#   - editing an NSG (opens the boundary)
#   - deleting a Key Vault or its keys (destroys or steals crypto material)
#   - changing Defender pricing tiers (turns off detection)
#   - creating role assignments (grants persistence)
#
# CIS Microsoft Azure Foundations v3.0.0 section 5.2 asks for activity log alerts
# on exactly this family of operations.
# ---------------------------------------------------------------------------

resource "azurerm_monitor_action_group" "security" {
  name                = "ag-${var.name_prefix}-security"
  resource_group_name = var.resource_group_name
  short_name          = substr("sec${var.name_prefix}", 0, 12)

  # IR-6: incident reporting has to reach a human on a schedule someone owns.
  # An empty list here is a valid deployment and an invalid control -- the
  # alerts still fire and are queryable, but nothing is pushed.
  dynamic "email_receiver" {
    for_each = toset(var.alert_notification_emails)
    content {
      name                    = "sec-${replace(replace(email_receiver.value, "@", "-at-"), ".", "-")}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }

  tags = var.tags
}

locals {
  activity_alerts = {
    policy_assignment_write = {
      operation   = "Microsoft.Authorization/policyAssignments/write"
      category    = "Administrative"
      description = "CIS Azure v3.0.0 5.2.1 / NIST CM-3: a policy assignment was created or modified. Weakening the baseline is step one of making everything else look compliant."
      severity    = 1
    }
    policy_assignment_delete = {
      operation   = "Microsoft.Authorization/policyAssignments/delete"
      category    = "Administrative"
      description = "CIS Azure v3.0.0 5.2.1 / NIST CM-3: a policy assignment was deleted. Guardrails are gone at that scope until this is investigated."
      severity    = 0
    }
    nsg_write = {
      operation   = "Microsoft.Network/networkSecurityGroups/write"
      category    = "Administrative"
      description = "CIS Azure v3.0.0 5.2.4 / NIST SC-7, CM-3: an NSG was created or modified. Boundary change."
      severity    = 1
    }
    nsg_rule_write = {
      operation   = "Microsoft.Network/networkSecurityGroups/securityRules/write"
      category    = "Administrative"
      description = "CIS Azure v3.0.0 5.2.5 / NIST SC-7: an individual NSG rule changed. This is the operation that opens 3389 to the internet."
      severity    = 1
    }
    key_vault_delete = {
      operation   = "Microsoft.KeyVault/vaults/delete"
      category    = "Administrative"
      description = "NIST SC-12 / SC-28: a Key Vault was deleted. Soft delete makes it recoverable; the attempt is still an incident."
      severity    = 0
    }
    security_pricing_write = {
      operation   = "Microsoft.Security/pricings/write"
      category    = "Administrative"
      description = "NIST SI-4 / CA-7: a Defender for Cloud plan tier changed. Downgrading a plan silently disables detections."
      severity    = 0
    }
    role_assignment_write = {
      operation   = "Microsoft.Authorization/roleAssignments/write"
      category    = "Administrative"
      description = "NIST AC-2(4) / AC-6: a role assignment was created. Privilege grants are the persistence mechanism in a cloud control plane."
      severity    = 1
    }
    diagnostic_setting_delete = {
      operation   = "Microsoft.Insights/diagnosticSettings/delete"
      category    = "Administrative"
      description = "NIST AU-9: a diagnostic setting was deleted. Someone stopped a resource from producing audit records."
      severity    = 0
    }
  }
}

resource "azurerm_monitor_activity_log_alert" "control_plane" {
  for_each = local.activity_alerts

  name                = "alert-${var.name_prefix}-${replace(each.key, "_", "-")}"
  resource_group_name = var.resource_group_name
  location            = "global"
  scopes              = ["/subscriptions/${var.subscription_id}"]
  description         = each.value.description
  enabled             = true

  criteria {
    category       = each.value.category
    operation_name = each.value.operation
  }

  action {
    action_group_id = azurerm_monitor_action_group.security.id
  }

  tags = merge(var.tags, {
    "control-family" = "AU"
    "severity"       = tostring(each.value.severity)
  })
}
