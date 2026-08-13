package main

import rego.v1

plan(resources) := {"resource_changes": resources}

sa(address, after) := {
	"address": address,
	"type": "azurerm_storage_account",
	"change": {"actions": ["create"], "after": after},
}

kv(address, after) := {
	"address": address,
	"type": "azurerm_key_vault",
	"change": {"actions": ["create"], "after": after},
}

test_denies_public_storage_account if {
	result := deny with input as plan([sa("azurerm_storage_account.archive", {
		"public_network_access_enabled": true,
		"tags": {},
	})])
	count(result) == 1
}

test_allows_private_storage_account if {
	result := deny with input as plan([sa("azurerm_storage_account.archive", {
		"public_network_access_enabled": false,
		"allow_nested_items_to_be_public": false,
		"tags": {},
	})])
	count(result) == 0
}

# The documented exception: the flow log sink is identified by tag, not by name.
test_allows_public_flow_log_sink if {
	result := deny with input as plan([sa("azurerm_storage_account.flow_logs", {
		"public_network_access_enabled": true,
		"tags": {"sink-purpose": "nsg-flow-logs"},
	})])
	count(result) == 0
}

test_denies_anonymous_blob_access if {
	result := deny with input as plan([sa("azurerm_storage_account.archive", {
		"public_network_access_enabled": false,
		"allow_nested_items_to_be_public": true,
		"tags": {},
	})])
	count(result) == 1
}

test_denies_public_key_vault if {
	result := deny with input as plan([kv("azurerm_key_vault.core", {
		"public_network_access_enabled": true,
		"enable_rbac_authorization": true,
		"purge_protection_enabled": true,
	})])
	count(result) == 1
}

test_denies_key_vault_access_policy_mode if {
	result := deny with input as plan([kv("azurerm_key_vault.core", {
		"public_network_access_enabled": false,
		"enable_rbac_authorization": false,
		"purge_protection_enabled": true,
	})])
	count(result) == 1
}

test_denies_key_vault_without_purge_protection if {
	result := deny with input as plan([kv("azurerm_key_vault.core", {
		"public_network_access_enabled": false,
		"enable_rbac_authorization": true,
		"purge_protection_enabled": false,
	})])
	count(result) == 1
}

test_allows_compliant_key_vault if {
	result := deny with input as plan([kv("azurerm_key_vault.core", {
		"public_network_access_enabled": false,
		"enable_rbac_authorization": true,
		"purge_protection_enabled": true,
	})])
	count(result) == 0
}

# A destroy plan must not trip anything -- these policies gate what is being
# created, not what is being torn down.
test_ignores_destroy_actions if {
	result := deny with input as plan([{
		"address": "azurerm_key_vault.core",
		"type": "azurerm_key_vault",
		"change": {"actions": ["delete"], "after": null},
	}])
	count(result) == 0
}
