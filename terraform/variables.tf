# ---------------------------------------------------------------------------
# Identity of the target tenant / subscription.
#
# No defaults. A compliance baseline that silently targets "whatever subscription
# the CLI happened to be logged into" is how you enforce FedRAMP High on a dev
# sandbox and nothing on production. Callers must be explicit.
# ---------------------------------------------------------------------------

variable "subscription_id" {
  description = "Subscription the provider authenticates against. In management_group scope this is the subscription hosting the shared logging/keys/network resources."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "tenant_id" {
  description = "Entra ID tenant GUID."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

# ---------------------------------------------------------------------------
# The two variables that change the shape of the whole deployment.
# ---------------------------------------------------------------------------

variable "fedramp_baseline" {
  description = <<-EOT
    Which FedRAMP Rev 5 baseline to enforce: "moderate" or "high".

    This is not cosmetic. It selects the built-in regulatory compliance initiative
    that gets assigned (FedRAMP Moderate vs FedRAMP High), and drives Log Analytics
    online retention, archive immutability windows, Defender for Servers plan tier,
    cryptographic key size and rotation cadence, and storage geo-replication. See
    local.baseline_matrix in locals.tf for the full parameter table.
  EOT
  type        = string
  default     = "moderate"

  validation {
    condition     = contains(["moderate", "high"], var.fedramp_baseline)
    error_message = "fedramp_baseline must be \"moderate\" or \"high\"."
  }
}

variable "deployment_scope" {
  description = <<-EOT
    "management_group" builds the MG hierarchy and assigns policy at MG scope.
    "single_subscription" skips every Microsoft.Management resource and assigns
    the same policy at subscription scope, so the module plans cleanly for someone
    who does not own the tenant root group.
  EOT
  type        = string
  default     = "management_group"

  validation {
    condition     = contains(["management_group", "single_subscription"], var.deployment_scope)
    error_message = "deployment_scope must be \"management_group\" or \"single_subscription\"."
  }
}

# ---------------------------------------------------------------------------
# Naming, placement, tagging.
# ---------------------------------------------------------------------------

variable "name_prefix" {
  description = "Short lowercase prefix for every generated resource name (3-10 chars)."
  type        = string
  default     = "cmpbase"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,9}$", var.name_prefix))
    error_message = "name_prefix must be 3-10 lowercase alphanumeric characters starting with a letter."
  }
}

variable "primary_location" {
  description = "Primary Azure region for the shared platform resources."
  type        = string
  default     = "usgovvirginia"
}

variable "secondary_location" {
  description = "Paired region used for geo-redundant archive. CP-9 / CP-10 want the audit archive out of the primary failure domain."
  type        = string
  default     = "usgovtexas"
}

variable "allowed_locations" {
  description = "Regions the allowed-locations policy permits. Default is the US Gov pair because FedRAMP boundaries are almost always geo-fenced (SC-7, AC-4)."
  type        = list(string)
  default     = ["usgovvirginia", "usgovtexas"]

  validation {
    condition     = length(var.allowed_locations) > 0
    error_message = "allowed_locations must not be empty; an empty list would deny every deployment."
  }
}

variable "allowed_vm_sku_sizes" {
  description = "VM SKUs permitted by the allowed-SKU policy. Constrains the attack surface and cost blast radius (CM-7 least functionality)."
  type        = list(string)
  default = [
    "Standard_D2s_v5",
    "Standard_D4s_v5",
    "Standard_D8s_v5",
    "Standard_E4s_v5",
    "Standard_B2ms",
  ]
}

variable "required_tags" {
  description = "Tag names every resource must carry. Backs the required-tags deny policy; these tags are what makes an inventory query answerable during an assessment (CM-8)."
  type        = list(string)
  default     = ["owner", "data-classification", "system-id"]
}

variable "tags" {
  description = "Extra tags merged over the module's own tags on every resource."
  type        = map(string)
  default     = {}
}

variable "system_id" {
  description = "FedRAMP system identifier / boundary name recorded on every resource so evidence exports can be scoped to one authorization boundary."
  type        = string
  default     = "unassigned"
}

# ---------------------------------------------------------------------------
# Management group hierarchy.
# ---------------------------------------------------------------------------

variable "root_management_group_display_name" {
  description = "Display name of the intermediate root MG this baseline owns. Deliberately NOT the tenant root group -- writing policy at the tenant root is a one-way door."
  type        = string
  default     = "Compliance Baseline Root"
}

variable "parent_management_group_id" {
  description = "Full resource ID of the parent MG. Null parents the intermediate root at the tenant root group, which requires Microsoft.Management registration and tenant-root-scope RBAC."
  type        = string
  default     = null
}

variable "subscription_associations" {
  description = "Map of management-group child key (platform, prod, nonprod, sandbox, decommissioned) to the list of subscription GUIDs to associate."
  type        = map(list(string))
  default     = {}

  validation {
    condition = alltrue([
      for k in keys(var.subscription_associations) :
      contains(["platform", "prod", "nonprod", "sandbox", "decommissioned"], k)
    ])
    error_message = "subscription_associations keys must be one of: platform, prod, nonprod, sandbox, decommissioned."
  }
}

# ---------------------------------------------------------------------------
# Policy.
# ---------------------------------------------------------------------------

variable "builtin_initiative_id_overrides" {
  description = <<-EOT
    Override map of initiative key -> policy set definition GUID. Use this to supply
    GUIDs this repo does not ship as verified (see local.builtin_initiatives).
    Verify with:
      az policy set-definition list --query "[?displayName=='<name>'].{n:displayName,id:name}" -o table
  EOT
  type        = map(string)
  default     = {}
}

variable "policy_assignment_enforcement" {
  description = "\"Default\" enforces policy effects; \"DoNotEnforce\" runs the whole baseline in what-if mode. Use DoNotEnforce for the first pass against a live tenant, then flip it."
  type        = string
  default     = "Default"

  validation {
    condition     = contains(["Default", "DoNotEnforce"], var.policy_assignment_enforcement)
    error_message = "policy_assignment_enforcement must be \"Default\" or \"DoNotEnforce\"."
  }
}

variable "policy_exemptions" {
  description = <<-EOT
    Documented, expiring exemptions. Every entry is a deviation that an assessor will
    ask about, so the schema forces a justification and an expiry -- a permanent
    exemption is a POA&M item pretending to be a config.
  EOT
  type = map(object({
    policy_assignment_key           = string
    scope_id                        = string
    category                        = optional(string, "Waiver")
    justification                   = string
    expires_on                      = string
    policy_definition_reference_ids = optional(list(string))
  }))
  default = {}

  validation {
    condition = alltrue([
      for e in values(var.policy_exemptions) :
      contains(["Waiver", "Mitigated"], e.category)
    ])
    error_message = "policy_exemptions category must be \"Waiver\" or \"Mitigated\"."
  }

  validation {
    condition = alltrue([
      for e in values(var.policy_exemptions) :
      can(formatdate("YYYY-MM-DD", e.expires_on))
    ])
    error_message = "policy_exemptions expires_on must be an RFC3339 timestamp (e.g. 2027-01-31T00:00:00Z)."
  }
}

variable "trust_unverified_initiative_ids" {
  description = "Opt in to the candidate initiative GUIDs this repo ships but has not verified. Off by default: assigning the wrong benchmark version produces a green dashboard against the wrong control set, which is worse than no dashboard."
  type        = bool
  default     = false
}

variable "guardrail_effect" {
  description = "Effect for the custom guardrail policies. Stage a rollout with \"Audit\", then move to \"Deny\"."
  type        = string
  default     = "Deny"

  validation {
    condition     = contains(["Deny", "Audit", "Disabled"], var.guardrail_effect)
    error_message = "guardrail_effect must be Deny, Audit or Disabled."
  }
}

variable "assessor_principal_ids" {
  description = "Entra object IDs granted Security Reader at the baseline scope. Assessors and the SOC read evidence; they do not write."
  type        = list(string)
  default     = []
}

variable "enable_regulatory_initiatives" {
  description = "Assign the built-in regulatory compliance initiatives (FedRAMP, NIST, CIS, MCSB). Free to assign; the audit-effect evaluations they trigger are free, DINE remediations are not."
  type        = bool
  default     = true
}

variable "enable_custom_guardrails" {
  description = "Assign the custom deny/audit policy set that covers the gaps the built-in initiatives leave open (regions, SKUs, tags, TLS, public blob, public IPs)."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Metered services. Every one of these costs money, so every one defaults off.
# ---------------------------------------------------------------------------

variable "enable_defender_for_cloud" {
  description = "Master switch for the Defender for Cloud module. Everything under it is metered."
  type        = bool
  default     = false
}

variable "enable_defender_servers" {
  description = "Defender for Servers. Tier follows fedramp_baseline (P1 for moderate, P2 for high -- P2 adds vulnerability assessment and FIM, which RA-5 and SI-7 want)."
  type        = bool
  default     = false
}

variable "enable_defender_storage" {
  description = "Defender for Storage (malware scanning + sensitive data discovery). SI-3."
  type        = bool
  default     = false
}

variable "enable_defender_sql" {
  description = "Defender for SQL on Azure SQL and SQL on VMs. SI-4, RA-5."
  type        = bool
  default     = false
}

variable "enable_defender_containers" {
  description = "Defender for Containers. Registry scanning and runtime threat detection. RA-5, SI-4."
  type        = bool
  default     = false
}

variable "enable_defender_key_vault" {
  description = "Defender for Key Vault. Anomalous key/secret access detection. AU-6, SI-4."
  type        = bool
  default     = false
}

variable "enable_defender_arm" {
  description = "Defender for Resource Manager. Detects hostile control-plane operations. AU-6, SI-4."
  type        = bool
  default     = false
}

variable "enable_defender_app_services" {
  description = "Defender for App Service. SI-4."
  type        = bool
  default     = false
}

variable "enable_defender_open_source_db" {
  description = "Defender for open-source relational databases (PostgreSQL/MySQL/MariaDB flexible servers). SI-4."
  type        = bool
  default     = false
}

variable "enable_defender_continuous_export" {
  description = "Continuous export of Defender alerts and assessments to Log Analytics (and Event Hub if configured). AU-6(3) audit correlation."
  type        = bool
  default     = false
}

variable "enable_logging" {
  description = "Log Analytics workspace, Activity Log diagnostic settings, DINE diagnostic policies and the immutable archive. Metered by ingestion and retention."
  type        = bool
  default     = true
}

variable "enable_immutable_archive" {
  description = "Immutable (WORM) storage account for long-term audit archive. AU-9(3), AU-11."
  type        = bool
  default     = true
}

variable "enable_encryption" {
  description = "Key Vault, customer-managed keys and the disk encryption set. Key Vault Premium (HSM) is metered per key and per operation."
  type        = bool
  default     = true
}

variable "enable_network" {
  description = "Baseline NSGs, Network Watcher, flow logs, private DNS and private endpoints."
  type        = bool
  default     = true
}

variable "enable_ddos_protection" {
  description = "Azure DDoS Network Protection plan. Roughly USD 2,900/month per tenant -- the single most expensive switch in this repo. SC-5."
  type        = bool
  default     = false
}

variable "enable_nsg_flow_logs" {
  description = "NSG flow logs to storage with traffic analytics. AU-2, AU-12, SC-7."
  type        = bool
  default     = false
}

variable "enable_private_endpoints" {
  description = "Private endpoints + private DNS zones for Key Vault and the archive account. SC-7(3) boundary protection via managed interfaces."
  type        = bool
  default     = false
}

variable "enable_defender_auto_provisioning" {
  description = "Auto-provision the monitoring agent so Defender for Servers has telemetry to work with. Without an agent, P2 degrades to agentless posture only."
  type        = bool
  default     = false
}

variable "enable_network_watcher" {
  description = "Create the Network Watcher instance. Azure creates one per region automatically in most tenants; set false to adopt the existing one instead of colliding with it."
  type        = bool
  default     = true
}

variable "deny_internet_egress" {
  description = "Add the explicit outbound-Internet deny to the baseline NSG. SC-7(4)/(5) target state, but it will break agent enrolment until a firewall or private-endpoint path exists."
  type        = bool
  default     = false
}

variable "flow_log_retention_days" {
  description = "NSG flow log retention in blob storage. AU-11 floor is 90 days for FedRAMP Moderate."
  type        = number
  default     = 90
}

variable "azure_environment" {
  description = "\"public\" or \"usgovernment\". Drives private DNS zone suffixes; getting this wrong makes private endpoints resolve to public IPs and silently defeats SC-7(3)."
  type        = string
  default     = "usgovernment"

  validation {
    condition     = contains(["public", "usgovernment"], var.azure_environment)
    error_message = "azure_environment must be \"public\" or \"usgovernment\"."
  }
}

variable "event_hub_resource_id" {
  description = "Event Hub resource ID for Defender continuous export."
  type        = string
  default     = null
}

variable "event_hub_connection_string" {
  description = "Send-only Event Hub connection string for Defender continuous export. Supply from a secret store at plan time; never commit it."
  type        = string
  default     = null
  sensitive   = true
}

variable "enable_event_hub_export" {
  description = "Stream Activity Log and Defender findings to an Event Hub for an external SIEM. Requires event_hub_authorization_rule_id."
  type        = bool
  default     = false
}

variable "event_hub_authorization_rule_id" {
  description = "Resource ID of the Event Hub namespace authorization rule used as the SIEM egress point. Required when enable_event_hub_export is true."
  type        = string
  default     = null
}

variable "event_hub_name" {
  description = "Event Hub name within the namespace to publish to."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Operational contacts and quotas.
# ---------------------------------------------------------------------------

variable "security_contact_emails" {
  description = "Addresses Defender for Cloud notifies on high-severity alerts. IR-6 incident reporting has to land somewhere a human reads."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.security_contact_emails : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[a-zA-Z]{2,}$", e))])
    error_message = "security_contact_emails must all be valid email addresses."
  }
}

variable "security_contact_phone" {
  description = "Phone number for Defender for Cloud security contact. Optional."
  type        = string
  default     = null
}

variable "log_analytics_daily_quota_gb" {
  description = "Daily ingestion cap in GB. -1 means uncapped. A cap protects the bill but can drop audit records, which is an AU-4 / AU-5 tradeoff you must make consciously."
  type        = number
  default     = -1
}

variable "alert_notification_emails" {
  description = "Recipients of the Activity Log alerts (policy assignment changes, NSG changes, Key Vault deletes). AU-6(1), SI-4(5)."
  type        = list(string)
  default     = []
}
