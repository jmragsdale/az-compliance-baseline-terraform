variable "name_prefix" {
  description = "Short prefix for generated names."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group hosting the continuous-export automations."
  type        = string
}

variable "location" {
  description = "Region for the continuous-export automation resources."
  type        = string
}

variable "subscription_id" {
  description = "Subscription GUID this Defender configuration applies to."
  type        = string
}

variable "fedramp_baseline" {
  description = "\"moderate\" or \"high\"."
  type        = string
}

variable "servers_subplan" {
  description = "Defender for Servers plan tier. P1 = agentless posture. P2 adds vulnerability assessment, file integrity monitoring and threat detection (RA-5, SI-7). Baseline-driven."
  type        = string

  validation {
    condition     = contains(["P1", "P2"], var.servers_subplan)
    error_message = "servers_subplan must be P1 or P2."
  }
}

variable "storage_malware_scanning" {
  description = "Enable on-upload malware scanning and sensitive data discovery in Defender for Storage. Metered per GB scanned. Baseline-driven (SI-3)."
  type        = bool
  default     = false
}

variable "log_analytics_workspace_id" {
  description = "Workspace Defender reports into and continuously exports to."
  type        = string
}

variable "enable_servers" {
  description = "Defender for Servers."
  type        = bool
  default     = false
}

variable "enable_storage" {
  description = "Defender for Storage."
  type        = bool
  default     = false
}

variable "enable_sql" {
  description = "Defender for Azure SQL and SQL on VMs."
  type        = bool
  default     = false
}

variable "enable_containers" {
  description = "Defender for Containers."
  type        = bool
  default     = false
}

variable "enable_key_vault" {
  description = "Defender for Key Vault."
  type        = bool
  default     = false
}

variable "enable_arm" {
  description = "Defender for Resource Manager."
  type        = bool
  default     = false
}

variable "enable_app_services" {
  description = "Defender for App Service."
  type        = bool
  default     = false
}

variable "enable_open_source_db" {
  description = "Defender for open-source relational databases."
  type        = bool
  default     = false
}

variable "enable_continuous_export" {
  description = "Continuous export of alerts, assessments and secure score to Log Analytics."
  type        = bool
  default     = false
}

variable "enable_auto_provisioning" {
  description = "Auto-provision the monitoring agent onto in-scope VMs so that Defender for Servers actually has telemetry (SI-4)."
  type        = bool
  default     = false
}

variable "security_contact_emails" {
  description = "Recipients of Defender for Cloud high-severity alerts (IR-6)."
  type        = list(string)
  default     = []
}

variable "security_contact_phone" {
  description = "Phone number for the security contact."
  type        = string
  default     = null
}

variable "event_hub_resource_id" {
  description = "Event Hub resource ID for continuous export to an external SIEM."
  type        = string
  default     = null
}

variable "event_hub_connection_string" {
  description = "Send-only Event Hub connection string. Pass from a secret store; never commit it."
  type        = string
  default     = null
  sensitive   = true
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
