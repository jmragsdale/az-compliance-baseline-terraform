# AU-11 audit record retention, checked against the resolved plan.
#
# The FedRAMP Rev 5 floor this repo enforces:
#   - Log Analytics interactive retention >= 365 days (Moderate), 730 (High)
#   - WORM immutability window >= 1095 days
#   - NSG flow logs >= 90 days
#   - Geo-redundant replication on the audit archive (CP-9)
#
# The point of checking this in policy rather than trusting the module is that
# `log_retention_days` is a variable. Someone will eventually set it to 30 to
# save money, and the module has no opinion about that. This does.

package main

import data.lib
import rego.v1

min_workspace_retention_days := 365

min_worm_days := 1095

min_flow_log_days := 90

geo_redundant_replication := {"GRS", "RAGRS", "GZRS", "RAGZRS"}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_log_analytics_workspace")
	retention := rc.change.after.retention_in_days
	lib.known(retention)
	retention < min_workspace_retention_days
	msg := sprintf(
		"%s: Log Analytics retention is %d days, below the AU-11 floor of %d. Audit records must outlive the dwell time of an intrusion, not the length of a billing cycle.",
		[rc.address, retention, min_workspace_retention_days],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_storage_account")
	some policy in rc.change.after.immutability_policy
	period := policy.period_since_creation_in_days
	lib.known(period)
	period < min_worm_days
	msg := sprintf(
		"%s: WORM immutability window is %d days, below the AU-9(3)/AU-11 floor of %d.",
		[rc.address, period, min_worm_days],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_storage_account")
	audit_archive(rc)
	not rc.change.after.account_replication_type in geo_redundant_replication
	msg := sprintf(
		"%s: audit archive uses replication %v. CP-9 / CP-10 require the audit archive to survive the loss of the primary region.",
		[rc.address, rc.change.after.account_replication_type],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_network_watcher_flow_log")
	some policy in rc.change.after.retention_policy
	days := policy.days
	lib.known(days)
	days < min_flow_log_days
	msg := sprintf(
		"%s: flow log retention is %d days, below the %d-day AU-11 floor.",
		[rc.address, days, min_flow_log_days],
	)
}

# AU-4/AU-5: an ingestion cap silently drops audit records once it is hit. That
# is defensible in a lab and indefensible inside an authorization boundary, so it
# is a warning rather than a denial -- the operator has to see it and decide.
warn contains msg if {
	some rc in lib.resources_of_type("azurerm_log_analytics_workspace")
	quota := rc.change.after.daily_quota_gb
	lib.known(quota)
	quota > 0
	msg := sprintf(
		"%s: daily ingestion is capped at %v GB. Once the cap is hit, audit records are DROPPED, not queued (AU-4, AU-5). Confirm this is a lab.",
		[rc.address, quota],
	)
}

audit_archive(rc) if {
	rc.change.after.tags["control-family"] == "AU"
	rc.change.after.tags["sink-purpose"] != "nsg-flow-logs"
}

audit_archive(rc) if {
	rc.change.after.tags["control-family"] == "AU"
	not rc.change.after.tags["sink-purpose"]
}
