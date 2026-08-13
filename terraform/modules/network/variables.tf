variable "name_prefix" {
  description = "Short prefix for generated names."
  type        = string
}

variable "unique_suffix" {
  description = "Deterministic suffix for globally-unique storage account names."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group hosting the platform network."
  type        = string
}

variable "location" {
  description = "Region."
  type        = string
}

variable "azure_environment" {
  description = "\"public\" or \"usgovernment\". Private DNS zone suffixes differ between clouds and getting this wrong produces private endpoints that resolve to nothing."
  type        = string
  default     = "usgovernment"

  validation {
    condition     = contains(["public", "usgovernment"], var.azure_environment)
    error_message = "azure_environment must be \"public\" or \"usgovernment\"."
  }
}

variable "vnet_address_space" {
  description = "Address space for the platform VNet."
  type        = list(string)
  default     = ["10.60.0.0/22"]
}

variable "private_endpoint_subnet_prefix" {
  description = "Prefix for the private endpoint subnet."
  type        = string
  default     = "10.60.0.0/24"
}

variable "workload_subnet_prefix" {
  description = "Prefix for the example workload subnet the baseline NSG is attached to."
  type        = string
  default     = "10.60.1.0/24"
}

variable "deny_internet_egress" {
  description = <<-EOT
    Add an explicit deny on outbound Internet traffic from the workload subnet.
    SC-7(4)/(5) wants egress denied by default, but turning this on without a
    firewall or service-endpoint path first will break agent enrolment, Windows
    Update and Key Vault access. Off by default so the baseline does not brick a
    tenant on first apply; turning it on is the target state.
  EOT
  type        = bool
  default     = false
}

variable "log_analytics_workspace_id" {
  description = "Workspace for NSG diagnostics and traffic analytics. Null disables both."
  type        = string
  default     = null
}

variable "log_analytics_workspace_guid" {
  description = "Workspace GUID (customer ID) required by traffic analytics."
  type        = string
  default     = null
}

variable "flow_log_retention_days" {
  description = "NSG flow log retention in storage. AU-11."
  type        = number
  default     = 90

  validation {
    condition     = var.flow_log_retention_days >= 90
    error_message = "flow_log_retention_days must be at least 90 to satisfy the FedRAMP Moderate audit retention floor."
  }
}

variable "enable_network_watcher" {
  description = "Create the Network Watcher instance. Azure auto-creates one per region; set false if yours already exists to avoid a name conflict."
  type        = bool
  default     = true
}

variable "enable_nsg_flow_logs" {
  description = "NSG flow logs plus traffic analytics. Metered by ingestion volume."
  type        = bool
  default     = false
}

variable "enable_ddos_protection" {
  description = "Azure DDoS Network Protection plan. ~USD 2,900/month per tenant."
  type        = bool
  default     = false
}

variable "enable_private_endpoints" {
  description = "Private endpoints and private DNS zones for Key Vault and the audit archive."
  type        = bool
  default     = false
}

variable "key_vault_id" {
  description = "Key Vault to place behind a private endpoint. Null skips it."
  type        = string
  default     = null
}

variable "archive_storage_account_id" {
  description = "Audit archive storage account to place behind a private endpoint. Null skips it."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
