package main

import rego.v1

gov_plan(resources) := {"resource_changes": resources}

assignment(after) := {
	"address": "module.policy.azurerm_management_group_policy_assignment.regulatory[\"fedramp_high\"]",
	"type": "azurerm_management_group_policy_assignment",
	"change": {"actions": ["create"], "after": after},
}

exemption(after) := {
	"address": "module.policy.azurerm_management_group_policy_exemption.this[\"legacy\"]",
	"type": "azurerm_management_group_policy_exemption",
	"change": {"actions": ["create"], "after": after},
}

compliant_assignment := {
	"identity": [{"type": "UserAssigned"}],
	"non_compliance_message": [{"content": "Blocked by the compliance baseline."}],
	"enforce": true,
}

test_allows_compliant_assignment if {
	result := deny with input as gov_plan([assignment(compliant_assignment)])
	count(result) == 0
}

test_denies_assignment_without_identity if {
	result := deny with input as gov_plan([assignment({
		"identity": [],
		"non_compliance_message": [{"content": "Blocked by the compliance baseline."}],
		"enforce": true,
	})])
	count(result) == 1
}

test_denies_assignment_without_non_compliance_message if {
	result := deny with input as gov_plan([assignment({
		"identity": [{"type": "UserAssigned"}],
		"non_compliance_message": [],
		"enforce": true,
	})])
	count(result) == 1
}

test_warns_on_do_not_enforce if {
	result := warn with input as gov_plan([assignment({
		"identity": [{"type": "UserAssigned"}],
		"non_compliance_message": [{"content": "Blocked by the compliance baseline."}],
		"enforce": false,
	})])
	count(result) == 1
}

test_denies_exemption_without_expiry if {
	result := deny with input as gov_plan([exemption({
		"expires_on": null,
		"description": "[Waiver] Vendor appliance pinned to TLS 1.1, tracked as POA&M-0042.",
	})])
	count(result) == 1
}

test_denies_exemption_without_justification if {
	result := deny with input as gov_plan([exemption({
		"expires_on": "2027-01-31T00:00:00Z",
		"description": "legacy",
	})])
	count(result) == 1
}

test_allows_documented_expiring_exemption if {
	result := deny with input as gov_plan([exemption({
		"expires_on": "2027-01-31T00:00:00Z",
		"description": "[Mitigated] Vendor appliance pinned to TLS 1.1; compensating reverse proxy. POA&M-0042.",
	})])
	count(result) == 0
}

test_denies_owner_role_assignment if {
	result := deny with input as gov_plan([{
		"address": "azurerm_role_assignment.oops",
		"type": "azurerm_role_assignment",
		"change": {"actions": ["create"], "after": {"role_definition_id": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}},
	}])
	count(result) == 1
}

test_allows_contributor_role_assignment if {
	result := deny with input as gov_plan([{
		"address": "module.policy.azurerm_role_assignment.remediation_contributor_mg[0]",
		"type": "azurerm_role_assignment",
		"change": {"actions": ["create"], "after": {"role_definition_id": "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"}},
	}])
	count(result) == 0
}
