output "key_vault_id" {
  description = "Resource ID of the compliance Key Vault."
  value       = azurerm_key_vault.core.id
}

output "key_vault_uri" {
  description = "Vault URI."
  value       = azurerm_key_vault.core.vault_uri
}

output "cmk_identity_id" {
  description = "Resource ID of the user-assigned identity holding wrap/unwrap on the CMKs."
  value       = azurerm_user_assigned_identity.cmk.id
}

output "cmk_identity_principal_id" {
  description = "Object ID of the CMK identity."
  value       = azurerm_user_assigned_identity.cmk.principal_id
}

output "storage_cmk_id" {
  description = "Versionless key ID for storage account CMK. Versionless so auto-rotation does not require a Terraform apply."
  value       = azurerm_key_vault_key.cmk["storage"].versionless_id
}

output "sql_cmk_id" {
  description = "Versionless key ID for SQL TDE protector."
  value       = azurerm_key_vault_key.cmk["sql"].versionless_id
}

output "disk_encryption_set_id" {
  description = "Resource ID of the disk encryption set to attach to managed disks."
  value       = azurerm_disk_encryption_set.this.id
}

output "key_rotation_summary" {
  description = "Human-readable summary of the cryptographic period actually in effect, for evidence exports."
  value = {
    key_size             = var.key_size
    rotation_period      = var.key_rotation_period
    expiry_period        = var.key_expiry_period
    key_type             = "RSA-HSM (FIPS 140-2 Level 3)"
    disk_encryption_type = azurerm_disk_encryption_set.this.encryption_type
  }
}
