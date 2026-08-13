# ---------------------------------------------------------------------------
# deployIfNotExists: diagnostic settings on everything.
#
# AU-2 and AU-12 require audit records from every component in the boundary. In
# Azure, a resource emits nothing to a workspace until someone attaches a
# diagnostic setting to it. Relying on humans to do that per resource is how a
# boundary ends up with 80% coverage and a blind spot exactly where the incident
# happens.
#
# DINE policy inverts it: the platform attaches the setting, on creation and
# retroactively via a remediation task, and reports every resource where it has
# not yet succeeded. That report is the AU-12 evidence.
#
# The remediation identity is passed in from the policy module so there is one
# principal with one reviewable set of role assignments, rather than a new
# identity per initiative.
# ---------------------------------------------------------------------------

locals {
  mg_scope = var.deployment_scope == "management_group"

  # Metrics are not offered by every resource provider. Requesting AllMetrics on
  # a provider that does not publish them makes the nested deployment fail, which
  # shows up as a permanently non-compliant resource and erodes trust in the
  # whole dashboard. So it is per-target.
  dine_targets = {
    keyvault = {
      resource_type = "Microsoft.KeyVault/vaults"
      display       = "Key Vault"
      metrics       = true
      rationale     = "AU-2 / CIS Azure v3.0.0 8.5: key and secret access is the highest-signal audit source in the tenant."
    }
    nsg = {
      resource_type = "Microsoft.Network/networkSecurityGroups"
      display       = "Network Security Group"
      metrics       = false
      rationale     = "AU-2 / SC-7: rule change history is what turns a firewall into an auditable boundary."
    }
    sql_database = {
      resource_type = "Microsoft.Sql/servers/databases"
      display       = "Azure SQL Database"
      metrics       = true
      rationale     = "AU-2 / AC-3: database-level audit records for access to data at the CUI boundary."
    }
    app_service = {
      resource_type = "Microsoft.Web/sites"
      display       = "App Service"
      metrics       = true
      rationale     = "AU-2 / SI-4: application console and HTTP logs for intrusion detection."
    }
    public_ip = {
      resource_type = "Microsoft.Network/publicIPAddresses"
      display       = "Public IP Address"
      metrics       = true
      rationale     = "AU-2 / SC-5: DDoS mitigation reports and flow counters at the boundary edge."
    }
  }

  # Monitoring Contributor. The DINE task needs to write a diagnostic setting on
  # the target resource; nothing more.
  diagnostics_role_id = "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
}

resource "azurerm_policy_definition" "diagnostics" {
  for_each = local.dine_targets

  name                = "${var.name_prefix}-diag-${each.key}"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deploy diagnostic settings for ${each.value.display} to the central workspace"
  description         = each.value.rationale
  management_group_id = local.mg_scope ? var.management_group_id : null

  metadata = jsonencode({
    category = "Monitoring"
    version  = "1.0.0"
  })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["DeployIfNotExists", "AuditIfNotExists", "Disabled"]
      defaultValue  = "DeployIfNotExists"
      metadata      = { displayName = "Effect" }
    }
    logAnalyticsWorkspaceId = {
      type     = "String"
      metadata = { displayName = "Target workspace", strongType = "omsWorkspace" }
    }
    settingName = {
      type         = "String"
      defaultValue = "compliance-baseline-diagnostics"
      metadata     = { displayName = "Diagnostic setting name" }
    }
  })

  policy_rule = jsonencode({
    # The "if" key is quoted deliberately. Unquoted, `if` is a bare HCL keyword
    # in object-key position and python-hcl2 (which Checkov and several other
    # scanners use) fails to parse the file at all -- silently, as a "parsing
    # error" rather than a finding. Terraform itself accepts either form.
    "if" = {
      field  = "type"
      equals = each.value.resource_type
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        name = "[parameters('settingName')]"
        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.Insights/diagnosticSettings/workspaceId"
              equals = "[parameters('logAnalyticsWorkspaceId')]"
            },
            {
              field  = "Microsoft.Insights/diagnosticSettings/logs.enabled"
              equals = "true"
            }
          ]
        }
        roleDefinitionIds = [local.diagnostics_role_id]
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              resourceName = { value = "[field('name')]" }
              location     = { value = "[field('location')]" }
              workspaceId  = { value = "[parameters('logAnalyticsWorkspaceId')]" }
              settingName  = { value = "[parameters('settingName')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                resourceName = { type = "string" }
                location     = { type = "string" }
                workspaceId  = { type = "string" }
                settingName  = { type = "string" }
              }
              resources = [
                {
                  type       = "${each.value.resource_type}/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('resourceName'), '/Microsoft.Insights/', parameters('settingName'))]"
                  location   = "[parameters('location')]"
                  properties = merge(
                    {
                      workspaceId = "[parameters('workspaceId')]"
                      # categoryGroup allLogs future-proofs the setting: new log
                      # categories a provider adds later are captured without a
                      # policy revision, which is the AU-2(3) review requirement
                      # met by design rather than by remembering.
                      logs = [
                        {
                          categoryGroup = "allLogs"
                          enabled       = true
                        }
                      ]
                    },
                    each.value.metrics ? {
                      metrics = [
                        {
                          category = "AllMetrics"
                          enabled  = true
                        }
                      ]
                    } : {}
                  )
                }
              ]
            }
          }
        }
      }
    }
  })
}

resource "azurerm_policy_set_definition" "diagnostics" {
  name                = "${var.name_prefix}-diagnostics"
  policy_type         = "Custom"
  display_name        = "Compliance baseline - centralized diagnostic settings"
  description         = "AU-2 / AU-12: every in-scope resource type emits audit records to the central workspace, deployed by policy rather than by hand."
  management_group_id = local.mg_scope ? var.management_group_id : null

  metadata = jsonencode({
    category = "Monitoring"
    version  = "1.0.0"
  })

  parameters = jsonencode({
    effect                  = { type = "String", allowedValues = ["DeployIfNotExists", "AuditIfNotExists", "Disabled"], defaultValue = "DeployIfNotExists" }
    logAnalyticsWorkspaceId = { type = "String" }
  })

  dynamic "policy_definition_reference" {
    for_each = azurerm_policy_definition.diagnostics
    content {
      reference_id         = policy_definition_reference.key
      policy_definition_id = policy_definition_reference.value.id
      parameter_values = jsonencode({
        effect                  = { value = "[parameters('effect')]" }
        logAnalyticsWorkspaceId = { value = "[parameters('logAnalyticsWorkspaceId')]" }
      })
    }
  }
}

locals {
  diagnostics_assignment_parameters = jsonencode({
    effect                  = { value = "DeployIfNotExists" }
    logAnalyticsWorkspaceId = { value = azurerm_log_analytics_workspace.core.id }
  })
}

resource "azurerm_management_group_policy_assignment" "diagnostics" {
  count = local.mg_scope ? 1 : 0

  name                 = "${var.name_prefix}-diagnostics"
  display_name         = "Compliance baseline - centralized diagnostic settings"
  description          = "AU-2, AU-12: attaches diagnostic settings to in-scope resources and reports the ones it has not yet reached."
  policy_definition_id = azurerm_policy_set_definition.diagnostics.id
  management_group_id  = var.management_group_id
  enforce              = var.enforcement_mode == "Default"
  location             = var.location
  parameters           = local.diagnostics_assignment_parameters

  identity {
    type         = "UserAssigned"
    identity_ids = [var.remediation_identity_id]
  }

  non_compliance_message {
    content = "This resource is not sending audit records to the central Log Analytics workspace. A remediation task will attach the diagnostic setting; if it fails, the remediation identity is missing Monitoring Contributor at this scope."
  }
}

resource "azurerm_subscription_policy_assignment" "diagnostics" {
  count = local.mg_scope ? 0 : 1

  name                 = "${var.name_prefix}-diagnostics"
  display_name         = "Compliance baseline - centralized diagnostic settings"
  description          = "AU-2, AU-12 scoped to a single subscription."
  policy_definition_id = azurerm_policy_set_definition.diagnostics.id
  subscription_id      = "/subscriptions/${var.subscription_id}"
  enforce              = var.enforcement_mode == "Default"
  location             = var.location
  parameters           = local.diagnostics_assignment_parameters

  identity {
    type         = "UserAssigned"
    identity_ids = [var.remediation_identity_id]
  }

  non_compliance_message {
    content = "This resource is not sending audit records to the central Log Analytics workspace."
  }
}
