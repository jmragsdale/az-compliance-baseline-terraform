variable "name_prefix" {
  description = "Short prefix for policy definition / assignment names."
  type        = string
}

variable "deployment_scope" {
  description = "\"management_group\" or \"single_subscription\"."
  type        = string
}

variable "management_group_id" {
  description = "Resource ID of the MG to define and assign policy at. Null in single_subscription mode."
  type        = string
  default     = null
}

variable "subscription_id" {
  description = "Subscription GUID used for subscription-scoped assignments."
  type        = string
}

variable "location" {
  description = "Region for the remediation managed identity and for the assignment identity location."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group hosting the remediation user-assigned identity."
  type        = string
}

variable "fedramp_baseline" {
  description = "\"moderate\" or \"high\" -- selects which FedRAMP initiative is assigned."
  type        = string
}

variable "primary_initiative_key" {
  description = "Key into local.builtin_initiatives for the baseline-selected FedRAMP initiative."
  type        = string
}

variable "builtin_initiative_id_overrides" {
  description = "Initiative key -> verified policy set definition GUID."
  type        = map(string)
  default     = {}
}

variable "trust_unverified_initiative_ids" {
  description = "Opt in to the candidate GUIDs this repo ships but has NOT verified. Off by default on purpose."
  type        = bool
  default     = false
}

variable "enable_regulatory_initiatives" {
  description = "Assign the built-in regulatory compliance initiatives."
  type        = bool
  default     = true
}

variable "enable_custom_guardrails" {
  description = "Assign the custom guardrail policy set."
  type        = bool
  default     = true
}

variable "enforcement_mode" {
  description = "\"Default\" or \"DoNotEnforce\"."
  type        = string
  default     = "Default"
}

variable "guardrail_effect" {
  description = "Effect applied to the custom guardrail policies: Deny, Audit or Disabled."
  type        = string
  default     = "Deny"

  validation {
    condition     = contains(["Deny", "Audit", "Disabled"], var.guardrail_effect)
    error_message = "guardrail_effect must be Deny, Audit or Disabled."
  }
}

variable "allowed_locations" {
  description = "Regions permitted by the allowed-locations guardrail."
  type        = list(string)
}

variable "allowed_vm_sku_sizes" {
  description = "VM SKUs permitted by the allowed-SKU guardrail."
  type        = list(string)
}

variable "required_tags" {
  description = "Tag names every taggable resource must carry."
  type        = list(string)
}

variable "exemptions" {
  description = "Documented, expiring policy exemptions keyed by a caller-chosen name."
  type = map(object({
    policy_assignment_key           = string
    scope_id                        = string
    category                        = optional(string, "Waiver")
    justification                   = string
    expires_on                      = string
    policy_definition_reference_ids = optional(list(string))
  }))
  default = {}
}

variable "tags" {
  description = "Tags applied to taggable resources in this module (the remediation identity)."
  type        = map(string)
  default     = {}
}
