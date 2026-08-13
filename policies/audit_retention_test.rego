package main

import rego.v1

retention_plan(resources) := {"resource_changes": resources}

workspace(after) := {
	"address": "module.logging.azurerm_log_analytics_workspace.core",
	"type": "azurerm_log_analytics_workspace",
	"change": {"actions": ["create"], "after": after},
}

archive(after) := {
	"address": "module.logging.azurerm_storage_account.archive",
	"type": "azurerm_storage_account",
	"change": {"actions": ["create"], "after": after},
}

test_denies_short_workspace_retention if {
	result := deny with input as retention_plan([workspace({
		"retention_in_days": 90,
		"daily_quota_gb": -1,
	})])
	count(result) == 1
}

test_allows_moderate_workspace_retention if {
	result := deny with input as retention_plan([workspace({
		"retention_in_days": 365,
		"daily_quota_gb": -1,
	})])
	count(result) == 0
}

test_allows_high_workspace_retention if {
	result := deny with input as retention_plan([workspace({
		"retention_in_days": 730,
		"daily_quota_gb": -1,
	})])
	count(result) == 0
}

test_warns_on_ingestion_cap if {
	result := warn with input as retention_plan([workspace({
		"retention_in_days": 365,
		"daily_quota_gb": 1,
	})])
	count(result) == 1
}

test_no_warning_when_uncapped if {
	result := warn with input as retention_plan([workspace({
		"retention_in_days": 365,
		"daily_quota_gb": -1,
	})])
	count(result) == 0
}

test_denies_short_worm_window if {
	result := deny with input as retention_plan([archive({
		"account_replication_type": "GRS",
		"immutability_policy": [{"period_since_creation_in_days": 365}],
		"tags": {"control-family": "AU"},
	})])
	count(result) == 1
}

test_allows_moderate_worm_window if {
	result := deny with input as retention_plan([archive({
		"account_replication_type": "GRS",
		"immutability_policy": [{"period_since_creation_in_days": 1095}],
		"tags": {"control-family": "AU"},
	})])
	count(result) == 0
}

test_denies_locally_redundant_audit_archive if {
	result := deny with input as retention_plan([archive({
		"account_replication_type": "LRS",
		"immutability_policy": [{"period_since_creation_in_days": 2555}],
		"tags": {"control-family": "AU"},
	})])
	count(result) == 1
}

test_denies_short_flow_log_retention if {
	result := deny with input as retention_plan([{
		"address": "module.network.azurerm_network_watcher_flow_log.baseline",
		"type": "azurerm_network_watcher_flow_log",
		"change": {"actions": ["create"], "after": {"retention_policy": [{"days": 30}]}},
	}])
	count(result) == 1
}

test_allows_compliant_flow_log_retention if {
	result := deny with input as retention_plan([{
		"address": "module.network.azurerm_network_watcher_flow_log.baseline",
		"type": "azurerm_network_watcher_flow_log",
		"change": {"actions": ["create"], "after": {"retention_policy": [{"days": 90}]}},
	}])
	count(result) == 0
}
