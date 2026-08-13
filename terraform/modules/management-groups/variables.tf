variable "name_prefix" {
  description = "Short prefix used to build management group names."
  type        = string
}

variable "root_display_name" {
  description = "Display name of the intermediate root management group."
  type        = string
}

variable "parent_management_group_id" {
  description = "Resource ID of the parent MG. Null parents at the tenant root group."
  type        = string
  default     = null
}

variable "subscription_associations" {
  description = "Map of child key -> list of subscription GUIDs to associate with that MG."
  type        = map(list(string))
  default     = {}
}
