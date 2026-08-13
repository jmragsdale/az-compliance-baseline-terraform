variable "name_prefix" {
  description = "Short prefix for generated names."
  type        = string
}

variable "unique_suffix" {
  description = "Deterministic suffix; Key Vault names are globally unique."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group hosting the vault and disk encryption set."
  type        = string
}

variable "location" {
  description = "Region."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant GUID that owns the vault."
  type        = string
}

variable "fedramp_baseline" {
  description = "\"moderate\" or \"high\"."
  type        = string
}

variable "key_size" {
  description = "RSA key size. Baseline-driven: 3072 for Moderate, 4096 for High (SC-12(1))."
  type        = number

  validation {
    condition     = contains([2048, 3072, 4096], var.key_size)
    error_message = "key_size must be 2048, 3072 or 4096."
  }
}

variable "key_rotation_period" {
  description = "ISO 8601 duration between automatic rotations. Baseline-driven (SC-12)."
  type        = string
}

variable "key_expiry_period" {
  description = "ISO 8601 duration after creation when a key version expires (SC-12)."
  type        = string
}

variable "key_notify_before" {
  description = "ISO 8601 duration before expiry to raise the near-expiry event."
  type        = string
}

variable "soft_delete_retention_days" {
  description = "Key Vault soft-delete window. 90 is the maximum and the only value worth using for audit-relevant key material."
  type        = number
  default     = 90

  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "soft_delete_retention_days must be between 7 and 90."
  }
}

variable "network_acl_bypass_azure_services" {
  description = "Allow trusted Azure services through the vault firewall. Required for disk encryption sets and CMK-encrypted storage to reach the key."
  type        = bool
  default     = true
}

variable "allowed_ip_rules" {
  description = "CIDRs permitted through the Key Vault firewall. Keep empty and use private endpoints; this exists for break-glass from a known bastion."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
