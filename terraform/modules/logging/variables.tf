variable "name_prefix" {
  description = "Short prefix for generated names."
  type        = string
}

variable "unique_suffix" {
  description = "Deterministic 6-char suffix used to make globally-unique storage account names."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group hosting the workspace and archive account."
  type        = string
}

variable "location" {
  description = "Primary region."
  type        = string
}

variable "secondary_location" {
  description = "Paired region, recorded on the archive account for CP-9 documentation."
  type        = string
}

variable "subscription_id" {
  description = "Subscription GUID whose Activity Log is captured."
  type        = string
}

variable "deployment_scope" {
  description = "\"management_group\" or \"single_subscription\"."
  type        = string
}

variable "management_group_id" {
  description = "MG to assign the diagnostic-settings DINE initiative at. Null in single_subscription mode."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Log Analytics interactive retention in days. Driven by fedramp_baseline (AU-11)."
  type        = number

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "Log Analytics interactive retention must be between 30 and 730 days."
  }
}

variable "archive_immutable_days" {
  description = "WORM immutability window on the archive account in days. Driven by fedramp_baseline (AU-9(3), AU-11)."
  type        = number
}

variable "archive_replication" {
  description = "Storage replication for the archive account (GRS / RAGRS). Driven by fedramp_baseline (CP-9)."
  type        = string

  validation {
    condition     = contains(["GRS", "RAGRS", "GZRS", "RAGZRS"], var.archive_replication)
    error_message = "archive_replication must be a geo-redundant option: GRS, RAGRS, GZRS or RAGZRS."
  }
}

variable "blob_soft_delete_days" {
  description = "Blob and container soft-delete window in days."
  type        = number
  default     = 30
}

variable "daily_quota_gb" {
  description = "Log Analytics daily ingestion cap in GB. -1 for uncapped."
  type        = number
  default     = -1
}

variable "enable_immutable_archive" {
  description = "Create the WORM archive storage account."
  type        = bool
  default     = true
}

variable "enable_event_hub_export" {
  description = "Also stream the Activity Log to Event Hub for an external SIEM."
  type        = bool
  default     = false
}

variable "event_hub_authorization_rule_id" {
  description = "Event Hub namespace authorization rule ID for SIEM egress."
  type        = string
  default     = null
}

variable "event_hub_name" {
  description = "Event Hub name."
  type        = string
  default     = null
}

variable "enforcement_mode" {
  description = "\"Default\" or \"DoNotEnforce\" for the DINE diagnostics assignment."
  type        = string
  default     = "Default"
}

variable "remediation_identity_id" {
  description = "Resource ID of the shared policy remediation user-assigned identity."
  type        = string
}

variable "alert_notification_emails" {
  description = "Recipients for control-plane change alerts."
  type        = list(string)
  default     = []
}

variable "key_vault_id" {
  description = "Compliance Key Vault whose audit events are captured. Null skips the diagnostic setting."
  type        = string
  default     = null
}

variable "cmk_key_vault_key_id" {
  description = "Versionless Key Vault key ID used to customer-manage the archive account's encryption. Null falls back to Microsoft-managed keys."
  type        = string
  default     = null
}

variable "cmk_identity_id" {
  description = "User-assigned identity with wrap/unwrap on cmk_key_vault_key_id. Required when cmk_key_vault_key_id is set."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
