# ---------------------------------------------------------------------------
# Customer-managed keys, one per data domain.
#
# SC-12 asks for key management; SC-12(1) for availability of key material;
# SC-13 for FIPS-validated cryptography. Separate keys per domain (storage,
# disks, SQL) is a deliberate blast-radius decision: destroying or rotating the
# storage key must not take every managed disk in the boundary offline.
#
# Rotation cadence is baseline-driven. Moderate rotates annually with a two-year
# key lifetime; High rotates every 180 days with a one-year lifetime. Automatic
# rotation matters more than the exact number: a manual rotation procedure is a
# procedure that stops happening in month 14.
#
# HSM-backed (RSA-HSM) so the private key never leaves FIPS 140-2 Level 3
# hardware, which is what SC-13 and the FedRAMP High crypto requirements want.
# ---------------------------------------------------------------------------

locals {
  cmk_keys = {
    storage = {
      purpose   = "Storage account and audit archive encryption"
      family    = "SC-28(1)"
      rationale = "Audit records at rest, including the WORM archive. Customer control of this key is what makes MP-6 sanitisation of audit media possible."
    }
    disks = {
      purpose   = "Managed disk encryption set"
      family    = "SC-28"
      rationale = "OS and data disks. Separate from storage so a disk key rotation cannot disturb the audit archive."
    }
    sql = {
      purpose   = "Azure SQL transparent data encryption"
      family    = "SC-28(1)"
      rationale = "Database TDE protector. Separated so a database compromise investigation can rotate the TDE key independently."
    }
  }
}

resource "azurerm_key_vault_key" "cmk" {
  #checkov:skip=CKV_AZURE_40:Checkov looks for a static expiration_date. These keys use a rotation_policy with expire_after, which expires every generated version automatically -- a hard-coded date would expire once and then silently stop protecting anything.
  for_each = local.cmk_keys

  name         = "cmk-${each.key}"
  key_vault_id = azurerm_key_vault.core.id

  # SC-13: HSM-backed RSA. Not software-protected RSA.
  key_type = "RSA-HSM"
  key_size = var.key_size

  key_opts = [
    "unwrapKey",
    "wrapKey",
  ]

  # SC-12: automatic rotation on a baseline-driven cryptographic period.
  rotation_policy {
    automatic {
      time_after_creation = var.key_rotation_period
    }
    expire_after         = var.key_expiry_period
    notify_before_expiry = var.key_notify_before
  }

  tags = merge(var.tags, {
    "control-family" = each.value.family
    "key-purpose"    = each.value.purpose
    "rotation"       = var.key_rotation_period
  })

  # The role assignment has to land before the data-plane key create, or the
  # first apply fails with a 403 that looks like a bug and is not.
  depends_on = [azurerm_role_assignment.deployer_crypto_officer]
}

# ---------------------------------------------------------------------------
# Disk encryption set.
#
# SC-28: managed disks encrypted with the customer key rather than the platform
# key. For the High baseline this is double encryption -- platform key AND
# customer key, two independent layers -- which is the configuration reviewers
# expect when the data classification justifies FedRAMP High in the first place.
#
# auto_key_rotation_enabled means the encryption set follows new key versions
# without an outage or a manual re-key, which is the difference between a
# rotation policy on paper and one that actually runs.
# ---------------------------------------------------------------------------

resource "azurerm_disk_encryption_set" "this" {
  name                = "des-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  key_vault_key_id    = azurerm_key_vault_key.cmk["disks"].id

  encryption_type = var.fedramp_baseline == "high" ? "EncryptionAtRestWithPlatformAndCustomerKeys" : "EncryptionAtRestWithCustomerKey"

  auto_key_rotation_enabled = true

  identity {
    type = "SystemAssigned"
  }

  tags = merge(var.tags, {
    "control-family" = "SC-28"
  })
}

# The encryption set's own identity needs unwrap rights, separately from the
# shared CMK identity. Same least-privilege role.
resource "azurerm_role_assignment" "des_encryption_user" {
  scope              = azurerm_key_vault.core.id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_crypto_service_encryption_user}"
  principal_id       = azurerm_disk_encryption_set.this.identity[0].principal_id
  principal_type     = "ServicePrincipal"

  description = "AC-6(1): the disk encryption set can unwrap its key and do nothing else in this vault."
}
