# Governance of the governance layer.
#
# The failure modes this catches are the ones that make a compliance baseline
# *look* deployed while doing nothing:
#
#   - an assignment containing deployIfNotExists policies with no managed
#     identity. It evaluates, it reports, it can never remediate, and the
#     dashboard stays red forever until someone stops looking at it.
#   - an assignment with no non-compliance message. The engineer whose deploy
#     just failed gets "disallowed by policy" and no way to find out which one,
#     so they open a ticket asking to have the policy removed.
#   - an exemption with no expiry. CA-5 expects a plan of action with milestones;
#     a permanent exemption is a POA&M item wearing a costume.
#   - `enforce = false` (DoNotEnforce), which is correct during a staged rollout
#     and catastrophic if it is still set six months later.

package main

import data.lib
import rego.v1

assignment_types := {
	"azurerm_management_group_policy_assignment",
	"azurerm_subscription_policy_assignment",
	"azurerm_resource_policy_assignment",
}

exemption_types := {
	"azurerm_management_group_policy_exemption",
	"azurerm_subscription_policy_exemption",
	"azurerm_resource_policy_exemption",
}

policy_assignments contains rc if {
	some rc in lib.changed_resources
	rc.type in assignment_types
}

policy_exemptions contains rc if {
	some rc in lib.changed_resources
	rc.type in exemption_types
}

deny contains msg if {
	some rc in policy_assignments
	count(object.get(rc.change.after, "identity", [])) == 0
	msg := sprintf(
		"%s: policy assignment has no managed identity. Any deployIfNotExists or modify policy inside it can evaluate but never remediate, which produces a permanently non-compliant dashboard row.",
		[rc.address],
	)
}

deny contains msg if {
	some rc in policy_assignments
	count(object.get(rc.change.after, "non_compliance_message", [])) == 0
	msg := sprintf(
		"%s: policy assignment has no non_compliance_message. Engineers hitting the deny get no way to find the responsible policy or the exemption process, and will escalate to have it removed.",
		[rc.address],
	)
}

deny contains msg if {
	some rc in policy_exemptions
	not lib.known(object.get(rc.change.after, "expires_on", null))
	msg := sprintf(
		"%s: policy exemption has no expiry. CA-5 expects deviations to be tracked with milestones; a permanent exemption is an untracked risk acceptance.",
		[rc.address],
	)
}

deny contains msg if {
	some rc in policy_exemptions
	description := object.get(rc.change.after, "description", "")
	count(description) < 20
	msg := sprintf(
		"%s: policy exemption has no meaningful justification. An assessor will ask why this resource is exempt and 'because it was' is not an answer.",
		[rc.address],
	)
}

# Correct during a staged rollout, a finding if it survives one.
warn contains msg if {
	some rc in policy_assignments
	rc.change.after.enforce == false
	msg := sprintf(
		"%s: assignment is in DoNotEnforce mode. Effects are simulated and nothing is blocked. Fine for the first pass against a live tenant; confirm this is intentional.",
		[rc.address],
	)
}

# AC-6(1): a remediation identity with Owner is a standing privilege escalation
# path from anyone who can author a policy definition.
deny contains msg if {
	some rc in lib.resources_of_type("azurerm_role_assignment")
	endswith(object.get(rc.change.after, "role_definition_id", ""), "/8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
	msg := sprintf(
		"%s: grants the Owner role. Nothing in this baseline needs Owner; the remediation identity uses Contributor plus Security Admin, scoped to the baseline scope (AC-6(1)).",
		[rc.address],
	)
}
