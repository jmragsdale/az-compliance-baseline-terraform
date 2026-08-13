# SC-7 boundary protection: nothing in the compliance baseline itself may be
# reachable from the public internet, with one documented exception.
#
# The exception is the NSG flow log sink. Network Watcher delivers flow logs from
# the platform network rather than from inside the VNet, so a private-endpoint-
# only account silently stops receiving records. That account is identified by
# its `sink-purpose` tag rather than by name, so the exception cannot be widened
# by renaming a resource.

package main

import data.lib
import rego.v1

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_storage_account")
	rc.change.after.public_network_access_enabled == true
	not flow_log_sink(rc)
	msg := sprintf(
		"%s: storage account allows public network access. NIST SC-7 requires the audit and key material stores to be reachable only over managed interfaces (private endpoints).",
		[rc.address],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_key_vault")
	rc.change.after.public_network_access_enabled == true
	msg := sprintf(
		"%s: Key Vault allows public network access. NIST SC-7 / SC-12: the root of trust is private-endpoint only.",
		[rc.address],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_storage_account")
	rc.change.after.allow_nested_items_to_be_public == true
	msg := sprintf(
		"%s: storage account permits anonymous blob access. NIST AC-22 / AC-3 -- this is the single most common cause of cloud data exposure.",
		[rc.address],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_key_vault")
	rc.change.after.enable_rbac_authorization == false
	msg := sprintf(
		"%s: Key Vault uses access policies instead of RBAC. Access policies are invisible to `az role assignment list` and to PIM, so AC-2/AC-6 reviews cannot see them.",
		[rc.address],
	)
}

deny contains msg if {
	some rc in lib.resources_of_type("azurerm_key_vault")
	rc.change.after.purge_protection_enabled == false
	msg := sprintf(
		"%s: Key Vault purge protection is disabled. A compromised Owner can delete and purge the vault inside the soft-delete window, destroying every CMK and every volume they protect (CP-9, SC-12).",
		[rc.address],
	)
}

flow_log_sink(rc) if {
	rc.change.after.tags["sink-purpose"] == "nsg-flow-logs"
}
