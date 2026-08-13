data "azurerm_client_config" "current" {}

# ---------------------------------------------------------------------------
# Key Vault: the root of trust for the boundary.
#
# SC-12 (key establishment and management) and SC-28(1) (protection of
# information at rest) both hinge on the customer, not the provider, controlling
# the key. That is what makes MP-6 media sanitisation achievable in a cloud you
# do not physically own: you cannot shred the disk, but you can destroy the key
# and render the ciphertext unrecoverable.
#
# Four design decisions worth defending:
#
#   RBAC instead of access policies. Access policies are a parallel authorization
#   system that does not appear in `az role assignment list`, is not covered by
#   PIM, and has no deny semantics. AC-2 / AC-6 reviews cannot see them. RBAC
#   mode is the only auditable option.
#
#   Purge protection ON. Without it, a compromised Owner can delete the vault and
#   purge it inside the soft-delete window, permanently destroying every key --
#   and with them every CMK-encrypted disk and storage account in the boundary.
#   This is an availability control (CP-9) as much as a security one. It cannot
#   be turned off once enabled, which is exactly the point.
#
#   Premium SKU + RSA-HSM keys. FIPS 140-2 Level 3 validated hardware. FedRAMP
#   High expects it; Moderate does not strictly require it but the cost delta is
#   trivial next to the argument you avoid having with an assessor.
#
#   Public network access disabled. SC-7: the vault is reachable over a private
#   endpoint from inside the boundary, and from nowhere else.
# ---------------------------------------------------------------------------

resource "azurerm_key_vault" "core" {
  #checkov:skip=CKV2_AZURE_32:The private endpoint for this vault is created in the network module (azurerm_private_endpoint.key_vault) because the subnet lives there. Checkov cannot follow the cross-module reference. public_network_access_enabled is false regardless.
  name                = substr("kv-${var.name_prefix}-${var.unique_suffix}", 0, 24)
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id

  # FIPS 140-2 Level 3 HSM backing.
  sku_name = "premium"

  rbac_authorization_enabled = true

  # CP-9 / SC-12: irreversible on purpose.
  purge_protection_enabled   = true
  soft_delete_retention_days = var.soft_delete_retention_days

  # SC-7: private endpoint only.
  public_network_access_enabled = false

  # Let the platform disk encryption service unwrap keys for the encryption set.
  enabled_for_disk_encryption = true

  # CM-7: ARM template and VM deployment integration are two more paths to the
  # key material that nothing in this baseline needs. Off.
  enabled_for_deployment          = false
  enabled_for_template_deployment = false

  network_acls {
    default_action = "Deny"
    bypass         = var.network_acl_bypass_azure_services ? "AzureServices" : "None"
    ip_rules       = var.allowed_ip_rules
  }

  tags = merge(var.tags, {
    "control-family" = "SC"
    "fips-level"     = "140-2-L3"
  })
}

# ---------------------------------------------------------------------------
# Identity used by data services to reach the key.
#
# AC-6(1): a dedicated identity holding exactly "Key Vault Crypto Service
# Encryption User" -- wrap and unwrap, nothing else. It cannot read a key, export
# a key, or list secrets. Compare with the common pattern of granting the storage
# account's system-assigned identity a broader crypto role because it was easier.
# ---------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "cmk" {
  name                = "id-${var.name_prefix}-cmk"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

locals {
  # Tenant-invariant built-in role GUIDs.
  role_crypto_service_encryption_user = "e147488a-f6f5-4113-8e2d-b22465e65bf6"
  role_crypto_officer                 = "14b46e9e-c2b7-41b4-b07b-48a6ebf60603"
}

resource "azurerm_role_assignment" "cmk_encryption_user" {
  scope              = azurerm_key_vault.core.id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_crypto_service_encryption_user}"
  principal_id       = azurerm_user_assigned_identity.cmk.principal_id
  principal_type     = "ServicePrincipal"

  description = "AC-6(1): wrap/unwrap only. This principal cannot read or export key material."
}

# The principal running Terraform needs Crypto Officer to create key versions and
# rotation policies. Scoped to this vault only, and it is a legitimate finding to
# raise if your pipeline identity is over-permissioned elsewhere.
resource "azurerm_role_assignment" "deployer_crypto_officer" {
  scope              = azurerm_key_vault.core.id
  role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/${local.role_crypto_officer}"
  principal_id       = data.azurerm_client_config.current.object_id

  description = "CM-5: the deployment principal can manage keys in this vault and nowhere else."
}
