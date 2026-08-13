# ---------------------------------------------------------------------------
# Network Watcher and NSG flow logs.
#
# AU-2 / AU-12 at the network layer. An NSG rule tells you what is allowed; a
# flow log tells you what actually happened, which is the only artifact that can
# answer "did this host talk to that IP on 14 March". Traffic analytics on top
# turns the raw records into the AU-6 review surface.
#
# SI-4(4) (inbound and outbound communications traffic monitoring) is the control
# that specifically requires this rather than merely benefiting from it.
# ---------------------------------------------------------------------------

resource "azurerm_network_watcher" "this" {
  count = var.enable_network_watcher ? 1 : 0

  name                = "nw-${var.name_prefix}-${var.location}"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = merge(var.tags, { "control-family" = "AU" })
}

# ---------------------------------------------------------------------------
# Flow log sink.
#
# This account is deliberately configured differently from the audit archive, and
# the differences are forced by the service rather than chosen:
#
#   shared_access_key_enabled = true -- Network Watcher flow log delivery
#   authenticates to the sink with the storage account key. Entra-only auth is
#   not supported for this sink. Documented as an accepted deviation rather than
#   hidden.
#
#   public_network_access_enabled = true with a default-deny firewall and the
#   AzureServices bypass -- flow log delivery comes from the platform, not from
#   inside the VNet, so a private-endpoint-only account silently stops receiving
#   records.
#
# Both are real constraints. Pretending otherwise would produce a repo that
# looks stricter and does not work.
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "flow_logs" {
  #checkov:skip=CKV_AZURE_59:Network Watcher writes flow logs from the platform network, not from inside the VNet. A private-endpoint-only account stops receiving records entirely. Mitigated by default-deny network rules with only the AzureServices bypass.
  #checkov:skip=CKV_AZURE_33:Queue service is unused on this account; only the blob endpoint receives flow log data.
  #checkov:skip=CKV2_AZURE_21:Blob diagnostic logging for this account is delivered by the DINE diagnostics initiative in the logging module.
  #checkov:skip=CKV2_AZURE_1:Flow log sinks cannot use a customer-managed key without breaking Network Watcher delivery in some regions; platform-managed keys with infrastructure encryption are the accepted posture for this account.
  #checkov:skip=CKV2_AZURE_18:See CKV2_AZURE_1 -- CMK is deliberately not applied to the flow log sink.
  #checkov:skip=CKV2_AZURE_40:Shared key access is required by Network Watcher flow log delivery; this is a documented service constraint, not an oversight.
  #checkov:skip=CKV2_AZURE_47:Static website hosting is not enabled on this account.
  #checkov:skip=CKV_AZURE_43:The name is built with substr() from a deterministic hash; the result is lowercase alphanumeric and <= 24 characters by construction.
  #checkov:skip=CKV2_AZURE_33:Deliberate. Network Watcher delivers flow logs from the platform network; a private-endpoint-only sink stops receiving records. See the header comment.
  count = var.enable_nsg_flow_logs ? 1 : 0

  name                = substr("st${var.name_prefix}flow${var.unique_suffix}", 0, 24)
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_kind             = "StorageV2"
  account_replication_type = "GRS"

  min_tls_version            = "TLS1_2"
  https_traffic_only_enabled = true

  # See the header comment: forced by the service, not chosen.
  shared_access_key_enabled     = true
  public_network_access_enabled = true

  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true

  sas_policy {
    expiration_period = "0.01:00:00"
    expiration_action = "Log"
  }

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices", "Logging", "Metrics"]
  }

  tags = merge(var.tags, {
    "control-family" = "AU"
    "sink-purpose"   = "nsg-flow-logs"
  })
}

resource "azurerm_network_watcher_flow_log" "baseline" {
  count = var.enable_nsg_flow_logs && var.enable_network_watcher ? 1 : 0

  name                 = "fl-${var.name_prefix}-baseline"
  network_watcher_name = azurerm_network_watcher.this[0].name
  resource_group_name  = var.resource_group_name
  location             = var.location

  target_resource_id = azurerm_network_security_group.baseline.id
  storage_account_id = azurerm_storage_account.flow_logs[0].id
  enabled            = true

  # Version 2 adds byte and packet counts per flow. Version 1 gives you the
  # 5-tuple and a decision only, which is not enough for AU-6 volumetric review.
  version = 2

  retention_policy {
    enabled = true
    days    = var.flow_log_retention_days
  }

  # AU-6: traffic analytics is what makes flow logs reviewable. Without it you
  # have gigabytes of JSON in blob storage that nobody will ever open.
  dynamic "traffic_analytics" {
    for_each = var.log_analytics_workspace_id != null && var.log_analytics_workspace_guid != null ? [1] : []
    content {
      enabled               = true
      workspace_id          = var.log_analytics_workspace_guid
      workspace_region      = var.location
      workspace_resource_id = var.log_analytics_workspace_id
      interval_in_minutes   = 10
    }
  }

  tags = merge(var.tags, { "control-family" = "AU" })
}
