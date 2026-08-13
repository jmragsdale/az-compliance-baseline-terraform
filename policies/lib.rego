# Shared helpers for the Conftest policies in this directory.
#
# These policies run against `terraform show -json tfplan` output, not against
# the HCL. That matters: they see the *resolved* values after variables,
# conditionals and baseline lookups have been evaluated, which is the only place
# a check like "retention is at least 365 days" can be honest. A check against
# HCL would see `var.log_retention_days` and have nothing to compare.

package lib

import rego.v1

# Resources being created or changed by this plan. A no-op or a delete is not
# something we should block.
changed_resources contains rc if {
	some rc in input.resource_changes
	some action in rc.change.actions
	action in {"create", "update"}
}

resources_of_type(type) := {rc |
	some rc in changed_resources
	rc.type == type
}

# Terraform renders unknown-at-plan-time values as null. Treating null as a
# violation produces noise on every plan that has not been applied yet, so
# helpers below only fire on values that are actually known.
known(value) if {
	value != null
}
