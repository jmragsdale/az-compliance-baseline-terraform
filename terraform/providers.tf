# Provider behaviour is pinned deliberately rather than left at defaults.
#
# `purge_soft_delete_on_destroy = false` and `recover_soft_deleted_*` exist because
# NIST 800-53 Rev 5 CP-9 / SI-12 and FedRAMP Rev 5 both treat audit and key material
# as records that must survive an accidental `terraform destroy`. A soft-deleted Key
# Vault that Terraform eagerly purges is an unrecoverable loss of the CMK protecting
# every encrypted volume in scope.
#
# `storage_use_azuread = true` removes shared-key data-plane auth from the toolchain
# itself, which is what IA-2 / AC-3 ask for at the identity layer (CIS Azure v3.0.0
# section 3 also calls out disabling shared key authorization).
provider "azurerm" {
  subscription_id     = var.subscription_id
  tenant_id           = var.tenant_id
  storage_use_azuread = true

  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
      recover_soft_deleted_keys       = true
    }

    resource_group {
      prevent_deletion_if_contains_resources = true
    }

    log_analytics_workspace {
      permanently_delete_on_destroy = false
    }
  }
}
