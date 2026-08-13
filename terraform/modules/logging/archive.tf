# ---------------------------------------------------------------------------
# WORM archive for audit records.
#
# AU-9 (protection of audit information) and AU-9(3) (cryptographic protection)
# ask a specific question: if the administrator who is being audited is the
# attacker, can they delete the evidence? In Azure the answer is "yes" for
# anything in a Log Analytics workspace they hold Contributor over. Immutable
# blob storage with a time-based retention policy is the answer that survives
# that threat model, because the storage service itself refuses the delete --
# not RBAC, not a policy, the service.
#
# AU-11 supplies the duration: 3 years for Moderate, 7 for High in this module.
#
# HONEST LIMITATION: the immutability policy is created in `Unlocked` state.
# Unlocked means an owner can still shorten or remove it. Locking it is
# irreversible for the life of the account -- not even Microsoft can unlock it --
# so a Terraform module that locks WORM on your behalf during a first apply is a
# module that has destroyed your ability to ever clean up a mistake. Locking is
# documented as a deliberate operational step in the README. An assessor will ask
# whether it is locked, and "Unlocked" is a finding.
# ---------------------------------------------------------------------------

resource "azurerm_storage_account" "archive" {
  #checkov:skip=CKV_AZURE_33:Queue service diagnostic logging is not configurable here -- shared key auth and public network access are both disabled, so Terraform has no data-plane path to the queue endpoint. The account stores blobs only; the queue endpoint is unused.
  #checkov:skip=CKV2_AZURE_21:Blob service diagnostic logging is delivered by the DINE diagnostic-settings initiative in dine.tf rather than a per-account resource, so that it applies to every storage account in the boundary and not just this one.
  #checkov:skip=CKV2_AZURE_47:Static website hosting is not enabled on this account; the property is unset rather than explicitly false.
  #checkov:skip=CKV_AZURE_43:The name is built with substr() from a deterministic hash; Checkov cannot evaluate the expression and assumes a violation. The resulting name is lowercase alphanumeric and <= 24 characters by construction.
  #checkov:skip=CKV_AZURE_36:bypass = ["AzureServices", "Logging", "Metrics"] is set on the network_rules block below. Checkov does not resolve it past the dynamic identity/customer_managed_key blocks in this resource.
  #checkov:skip=CKV2_AZURE_33:The private endpoint for this account is created in the network module (azurerm_private_endpoint.archive_blob) because the subnet lives there. Checkov cannot follow the cross-module reference.
  count = var.enable_immutable_archive ? 1 : 0

  name                = substr("st${var.name_prefix}arch${var.unique_suffix}", 0, 24)
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier = "Standard"
  account_kind = "StorageV2"

  # CP-9 / CP-10: the audit archive must survive the loss of the primary region.
  # High baseline uses RAGRS so the secondary copy is readable during a regional
  # outage rather than only after a failover.
  account_replication_type = var.archive_replication
  access_tier              = "Cool"

  # SC-8(1): TLS 1.2 floor on the data plane.
  min_tls_version            = "TLS1_2"
  https_traffic_only_enabled = true

  # AC-3 / IA-2: shared keys are bearer credentials that cannot be scoped,
  # rotated per-principal, or attributed to a human in the audit log. Entra ID
  # auth only.
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true

  # AC-22: no anonymous read paths into the audit archive, ever.
  allow_nested_items_to_be_public = false

  # SC-7: reachable only over private endpoints (see the network module).
  public_network_access_enabled = false

  # SC-28(1): double encryption at rest -- the platform layer plus the
  # infrastructure layer, which is what FedRAMP High reviewers look for.
  infrastructure_encryption_enabled = true

  # SC-12: a SAS token with a long life is an unrevocable credential. One hour.
  sas_policy {
    expiration_period = "0.01:00:00"
    expiration_action = "Log"
  }

  # AU-9(3): time-based WORM. Nothing written can be modified or deleted for the
  # retention period, including by an account owner.
  immutability_policy {
    allow_protected_append_writes = true
    state                         = "Unlocked"
    period_since_creation_in_days = var.archive_immutable_days
  }

  blob_properties {
    # Account-level immutability requires versioning. It is also what makes an
    # overwrite recoverable rather than destructive (SI-12).
    versioning_enabled = true

    # AU-6(3): the change feed is an ordered, durable log of every blob mutation,
    # which is the audit trail *of the audit archive itself*.
    change_feed_enabled           = true
    change_feed_retention_in_days = var.blob_soft_delete_days

    last_access_time_enabled = true

    delete_retention_policy {
      days = var.blob_soft_delete_days
    }

    container_delete_retention_policy {
      days = var.blob_soft_delete_days
    }
  }

  # SC-7(3): default deny. AzureServices bypass is required for Log Analytics
  # continuous export and Defender continuous export to write here at all.
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices", "Logging", "Metrics"]
  }

  dynamic "identity" {
    for_each = var.cmk_identity_id != null ? [1] : []
    content {
      type         = "UserAssigned"
      identity_ids = [var.cmk_identity_id]
    }
  }

  # SC-12 / SC-28(1): customer-managed key so that key destruction is a
  # customer-controlled sanitisation mechanism (MP-6).
  dynamic "customer_managed_key" {
    for_each = var.cmk_key_vault_key_id != null && var.cmk_identity_id != null ? [1] : []
    content {
      key_vault_key_id          = var.cmk_key_vault_key_id
      user_assigned_identity_id = var.cmk_identity_id
    }
  }

  tags = merge(var.tags, {
    "control-family"    = "AU"
    "worm-days"         = tostring(var.archive_immutable_days)
    "paired-region"     = var.secondary_location
    "immutability-lock" = "unlocked-see-readme"
  })
}

resource "azurerm_storage_container" "archive" {
  #checkov:skip=CKV2_AZURE_21:Blob read logging is delivered estate-wide by the DINE diagnostics initiative in dine.tf, plus the account-level diagnostic setting below, rather than per-container.
  count = var.enable_immutable_archive ? 1 : 0

  name                  = "audit-archive"
  storage_account_id    = azurerm_storage_account.archive[0].id
  container_access_type = "private"
}

# AU-4: seven years of hot-tier audit logs is a five-figure annual line item for
# no operational benefit. Tiering keeps the records (AU-11) at roughly a tenth of
# the cost. Retrieval from Archive tier takes hours, which is acceptable for
# forensic lookback and is why the online workspace exists in parallel.
resource "azurerm_storage_management_policy" "archive" {
  count = var.enable_immutable_archive ? 1 : 0

  storage_account_id = azurerm_storage_account.archive[0].id

  rule {
    name    = "audit-archive-tiering"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["audit-archive/"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_archive_after_days_since_modification_greater_than = 180
        # Deliberately no delete_after_days: the WORM policy owns the lifetime.
        # A lifecycle delete racing an immutability policy produces a permanently
        # failing rule and a misleading "policy applied" status.
      }

      version {
        # The version/snapshot blocks use the change_tier_* spelling; only
        # base_blob uses tier_to_*. Same concept, different argument names.
        change_tier_to_cool_after_days_since_creation    = 30
        change_tier_to_archive_after_days_since_creation = 180
      }
    }
  }
}

# AU-6: the archive account's own control plane is audited into the workspace.
# Someone attempting to weaken the immutability policy shows up here.
resource "azurerm_monitor_diagnostic_setting" "archive_account" {
  count = var.enable_immutable_archive ? 1 : 0

  name                       = "diag-${var.name_prefix}-archive"
  target_resource_id         = "${azurerm_storage_account.archive[0].id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.core.id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }

  enabled_metric {
    category = "Transaction"
  }
}
