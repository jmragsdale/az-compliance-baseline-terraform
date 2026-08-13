<!-- GENERATED FILE - do not edit by hand.
     Source: controls/controls.yaml   Regenerate: python3 controls/render.py -->

# Control Matrix - Microsoft Azure

74 implemented controls, each backed by a Terraform address that CI verifies exists.

## Framework coverage

| Framework | Version | Controls implemented | Distinct framework IDs mapped |
|---|---|---:|---:|
| FedRAMP Rev 5 (Moderate / High) | Rev 5 | 73 / 74 | 46 |
| NIST SP 800-53 Rev 5 | Rev 5 | 74 / 74 | 76 |
| CIS Microsoft Azure Foundations Benchmark | v3.0.0 | 67 / 74 | 24 |

> **Read this honestly:** these numbers count *technical* controls implemented in Terraform. They are not an assessment, an ATO, or a claim of full baseline coverage. Administrative and procedural control families (AT, PS, PE, and much of PL/PM) cannot be implemented in infrastructure code at all.

## Enforcement split

| Type | Count | Meaning |
|---|---:|---|
| preventive | 36 | blocks the non-compliant configuration from being created |
| detective | 24 | detects and reports the non-compliant configuration |
| foundational | 14 | provides the substrate other controls depend on (logging, keys, scope) |

## Matrix

| ID | Control | Type | Module | FedRAMP R5 | NIST R5 | CIS Azure v3.0.0 | Demo-safe | Billable |
|---|---|---|---|---|---|---|---|---|
| `DAT-001` | Write-once, read-many immutability on the audit archive | preventive | `logging` | AU-9, AU-11 | AU-9, AU-9(3), AU-11 | 3 | yes | yes |
| `DAT-002` | Blob versioning and change feed on the audit archive | preventive | `logging` | SI-12, AU-9 | SI-12, AU-9, AU-6(3) | 3 | yes | yes |
| `DAT-003` | Blob and container soft delete windows | preventive | `logging` | CP-9, SI-12 | CP-9, SI-12 | 3 | yes | yes |
| `DAT-004` | Geo-redundant audit archive with a readable secondary at High | preventive | `logging` | CP-9, CP-10 | CP-9, CP-10, CP-6 | 3 | yes | yes |
| `DAT-005` | Shared key authentication disabled on the audit archive | preventive | `logging` | AC-3, IA-2 | AC-3, IA-2, IA-5 | 3 | yes | no |
| `DAT-006` | SAS token lifetime capped at one hour | preventive | `logging` | AC-3, SC-12 | AC-3, IA-5, SC-12 | 3.3 | yes | no |
| `DAT-007` | Lifecycle tiering keeps long retention affordable | foundational | `logging` | AU-4, AU-11 | AU-4, AU-11 | - | yes | yes |
| `DAT-008` | Storage and Key Vault firewalls default to deny | preventive | `encryption` | SC-7, AC-3 | SC-7, SC-7(5), AC-3 | 3, 8 | yes | no |
| `DET-001` | Defender for Cloud plans behind individual enable_* switches | detective | `defender` | RA-5, SI-4 | RA-5, SI-4, CA-7 | 2.1 | no | yes |
| `DET-002` | Defender for Servers tier selected by the FedRAMP baseline | detective | `defender` | RA-5, SI-7 | RA-5, SI-7, SI-7(1) | 2.1 | no | yes |
| `DET-003` | Malware scanning and sensitive data discovery on storage at the High baseline | detective | `defender` | SI-3, RA-2 | SI-3, RA-2, SI-4 | 2.1 | no | yes |
| `DET-004` | Security contacts so high-severity alerts reach a human | detective | `defender` | IR-6, SI-4 | IR-6, IR-6(1), SI-4(5) | 2 | no | no |
| `DET-005` | Monitoring agent auto-provisioning for server telemetry | detective | `defender` | SI-4 | SI-4, SI-4(2) | 2 | no | yes |
| `DET-006` | Defender findings land in the same workspace as the Activity Log | detective | `defender` | AU-6 | AU-6, AU-6(3) | 2 | no | yes |
| `DET-007` | Continuous export of alerts, assessments and secure score | detective | `defender` | CA-7, AU-11 | CA-7, AU-11, AU-6(3) | 2 | no | yes |
| `DET-008` | Findings streamed to an external SIEM via Event Hub | detective | `defender` | AU-9, IR-4 | AU-9(2), IR-4, SI-4 | - | no | yes |
| `DET-009` | Custom Defender assessment for un-locked WORM policies | detective | `defender` | AU-9 | AU-9, AU-9(3) | 3 | no | no |
| `DET-010` | Defender for Endpoint and Cloud Apps integrations set explicitly | detective | `defender` | SI-4, SI-3 | SI-3, SI-4 | 2 | no | yes |
| `DET-011` | Activity Log alerts on control-plane operations that weaken the baseline | detective | `logging` | AU-6, SI-4, CM-3 | AU-6(1), SI-4(5), CM-3, AC-2(4) | 5.2 | yes | no |
| `DET-012` | Action group routing security alerts to named recipients | detective | `logging` | IR-6 | IR-6, AU-6(1) | 5.2 | yes | no |
| `ENC-001` | Key Vault with purge protection and maximum soft-delete window | foundational | `encryption` | SC-12, CP-9 | SC-12, SC-12(1), CP-9 | 8 | yes | yes |
| `ENC-002` | HSM-backed customer-managed keys, one per data domain | foundational | `encryption` | SC-12, SC-13, SC-28 | SC-12, SC-13, SC-28, SC-28(1) | 8 | yes | yes |
| `ENC-003` | Automatic key rotation on a baseline-driven cryptographic period | foundational | `encryption` | SC-12 | SC-12, SC-12(1) | 8.1 | yes | yes |
| `ENC-004` | Disk encryption set with double encryption at the High baseline | preventive | `encryption` | SC-28 | SC-28, SC-28(1) | 7 | yes | yes |
| `ENC-005` | Audit archive encrypted with a customer-controlled key | preventive | `logging` | SC-28, MP-6 | SC-28(1), MP-6, SC-12 | 3 | yes | yes |
| `ENC-006` | Infrastructure-level double encryption on stored audit records | preventive | `logging` | SC-28 | SC-28, SC-28(1) | 3.2 | yes | yes |
| `IAM-001` | Dedicated, long-lived remediation identity for deployIfNotExists | foundational | `policy` | AC-2, AC-6 | AC-2, AC-2(7), AC-6 | 1 | yes | no |
| `IAM-002` | Remediation identity scoped to the baseline scope, never tenant root | preventive | `policy` | AC-6 | AC-6, AC-6(1), AC-6(5) | 1 | yes | no |
| `IAM-003` | Defender configuration rights granted without Owner | preventive | `policy` | AC-6 | AC-6, AC-6(1) | 1 | yes | no |
| `IAM-004` | Diagnostic-settings remediation limited to monitoring roles | preventive | `policy` | AC-6, AU-12 | AC-6(1), AU-12 | 5.1 | yes | no |
| `IAM-005` | Read-only evidence access for assessors via Security Reader | preventive | `root` | AC-2, CA-2 | AC-2, AC-6(1), CA-2, AU-6 | 1 | yes | no |
| `IAM-006` | Key Vault in RBAC mode instead of access policies | preventive | `encryption` | AC-3, AC-6 | AC-3, AC-6, AU-6 | 8 | yes | no |
| `IAM-007` | Crypto identities hold wrap/unwrap only, not key read or export | preventive | `encryption` | AC-6, SC-12 | AC-6(1), SC-12 | 8 | yes | no |
| `IAM-008` | Deployment principal's key management rights scoped to one vault | preventive | `encryption` | CM-5, AC-6 | CM-5, AC-6(1) | 8 | yes | no |
| `LOG-001` | Single central Log Analytics workspace for the boundary | foundational | `logging` | AU-2, AU-3, AU-6 | AU-2, AU-3, AU-6, AU-12 | 5.1 | yes | yes |
| `LOG-002` | Audit retention window driven by the FedRAMP baseline | foundational | `logging` | AU-11 | AU-11, AU-4 | 5.1 | yes | yes |
| `LOG-003` | Subscription Activity Log captured to the central workspace | detective | `logging` | AU-2, AU-3, AU-12 | AU-2, AU-3, AU-12 | 5.1 | yes | yes |
| `LOG-004` | Audit records copied to a system the subscription owner cannot administer | detective | `logging` | AU-9 | AU-9, AU-9(2) | 5.1 | no | yes |
| `LOG-005` | deployIfNotExists policies attaching diagnostic settings by resource type | preventive | `logging` | AU-2, AU-12 | AU-2, AU-12, CM-6 | 5.1 | yes | no |
| `LOG-006` | Diagnostics initiative assigned with a remediation identity | preventive | `logging` | AU-12, CM-6 | AU-12, CM-6 | 5.1 | yes | no |
| `LOG-007` | Key Vault audit events captured | detective | `logging` | AU-2, AU-6 | AU-2, AU-6, SC-12 | 8.5 | yes | yes |
| `LOG-008` | The audit archive's own control plane is audited | detective | `logging` | AU-9 | AU-9, AU-6(3) | 5.1 | yes | yes |
| `LOG-009` | Ingestion cap is opt-in and its consequence is stated | foundational | `logging` | AU-4, AU-5 | AU-4, AU-5 | - | yes | yes |
| `MG-001` | Intermediate root management group owned by the baseline | foundational | `management-groups` | CM-2, AC-3 | CM-2, AC-3, PM-5 | 1 | no | no |
| `MG-002` | Platform management group isolating shared services | foundational | `management-groups` | CM-2, CM-5, SC-7 | CM-2, CM-5, SC-7 | 1 | no | no |
| `MG-003` | Production / non-production landing zone separation | foundational | `management-groups` | CM-2, SC-7, CM-4 | CM-2, CM-4, SC-7 | 1 | no | no |
| `MG-004` | Sandbox management group declared outside the authorization boundary | foundational | `management-groups` | CA-3, SA-9 | CA-3, SA-9, PL-2 | 1 | no | no |
| `MG-005` | Decommissioned management group preserving the disposal audit trail | foundational | `management-groups` | MP-6 | MP-6, SR-12, CM-8 | - | no | no |
| `MG-006` | Additive subscription placement into the hierarchy | foundational | `management-groups` | CM-8, CM-2 | CM-8, CM-2 | 1 | no | no |
| `NET-001` | Baseline network security group applied to workload subnets | preventive | `network` | SC-7 | SC-7, AC-4 | 6 | yes | no |
| `NET-002` | Remote management and database ports denied from the internet | preventive | `network` | AC-17, SC-7 | AC-17, AC-17(1), SC-7 | 6.1, 6.2 | yes | no |
| `NET-003` | Explicit terminal deny on inbound traffic | preventive | `network` | SC-7 | SC-7, SC-7(5) | 6 | yes | no |
| `NET-004` | Opt-in deny on unrestricted internet egress | preventive | `network` | SC-7 | SC-7(4), SC-7(5), AC-4 | 6 | yes | no |
| `NET-005` | Network Watcher present in the region | detective | `network` | AU-12, SI-4 | AU-12, SI-4(4) | 6.5 | yes | no |
| `NET-006` | NSG flow logs with traffic analytics | detective | `network` | AU-2, AU-12, SI-4 | AU-2, AU-12, SI-4(4) | 6.6 | no | yes |
| `NET-007` | Private endpoints for the Key Vault and the audit archive | preventive | `network` | SC-7 | SC-7, SC-7(3) | 8.6 | no | yes |
| `NET-008` | Cloud-correct private DNS zones linked to the platform VNet | preventive | `network` | SC-7, SC-20 | SC-7(3), SC-20, SC-21 | 6 | no | yes |
| `NET-009` | Private endpoint subnet keeps network policies enabled | preventive | `network` | SC-7 | SC-7, SC-7(3) | 6 | yes | no |
| `NET-010` | DDoS Network Protection plan | preventive | `network` | SC-5 | SC-5, SC-5(1) | 6 | no | yes |
| `NET-011` | NSG rule change history captured | detective | `network` | AU-2, CM-3 | AU-2, CM-3, SC-7 | 5.1 | yes | yes |
| `POL-001` | FedRAMP baseline initiative assigned at management group scope | detective | `policy` | CA-2, CA-7, CM-6 | CA-2, CA-7, CM-6, PM-31 | 2 | no | no |
| `POL-002` | Same regulatory initiatives assignable at subscription scope | detective | `policy` | CA-2, CA-7 | CA-2, CA-7 | 2 | yes | no |
| `POL-003` | NIST SP 800-53 Rev 5 initiative assigned alongside the FedRAMP baseline | detective | `policy` | CA-2, CA-7 | CA-2, CA-7, PM-31 | - | yes | no |
| `POL-004` | CIS Microsoft Azure Foundations v3.0.0 initiative (GUID verification required) | detective | `policy` | - | CA-2, CA-7 | 1, 2, 3, 4, 5, 6, 7, 8, 9 | yes | no |
| `POL-005` | Microsoft Cloud Security Benchmark initiative assigned explicitly | detective | `policy` | CA-7, CM-6 | CA-7, CM-6 | 2 | yes | no |
| `POL-006` | Deny resources outside approved regions | preventive | `policy` | SC-7, AC-4 | SC-7, AC-4, SA-9 | 10 | yes | no |
| `POL-007` | Deny virtual machines outside the approved SKU list | preventive | `policy` | CM-7 | CM-7, SA-22 | 7 | yes | no |
| `POL-008` | Deny resources missing required inventory tags | preventive | `policy` | CM-8 | CM-8, PM-5, RA-2 | 10 | yes | no |
| `POL-009` | Deny storage accounts below the minimum TLS version | preventive | `policy` | SC-8, SC-13 | SC-8, SC-8(1), SC-13 | 3.12 | yes | no |
| `POL-010` | Deny storage accounts that allow anonymous blob access | preventive | `policy` | AC-3, AC-22 | AC-3, AC-22 | 3.7 | yes | no |
| `POL-011` | Deny network interfaces with a directly attached public IP | preventive | `policy` | SC-7 | SC-7, SC-7(4) | 6 | yes | no |
| `POL-012` | Custom guardrails packaged as one initiative with one assignment | preventive | `policy` | CM-6, CM-7 | CM-6, CM-7 | 10 | yes | no |
| `POL-013` | Policy effect is stageable from Audit to Deny without code changes | preventive | `policy` | CM-3, CM-4 | CM-3, CM-4, SA-11 | - | yes | no |
| `POL-014` | Documented, expiring policy exemptions | preventive | `policy` | CA-5, RA-3 | CA-5, RA-3, CM-3 | - | yes | no |

## Implementation index

Terraform addresses backing each control. CI fails if any of these stop existing.

| ID | Terraform addresses |
|---|---|
| `DAT-001` | `logging:azurerm_storage_account.archive`, `logging:azurerm_storage_container.archive` |
| `DAT-002` | `logging:azurerm_storage_account.archive` |
| `DAT-003` | `logging:azurerm_storage_account.archive` |
| `DAT-004` | `logging:azurerm_storage_account.archive` |
| `DAT-005` | `logging:azurerm_storage_account.archive` |
| `DAT-006` | `logging:azurerm_storage_account.archive`, `network:azurerm_storage_account.flow_logs` |
| `DAT-007` | `logging:azurerm_storage_management_policy.archive` |
| `DAT-008` | `encryption:azurerm_key_vault.core`, `logging:azurerm_storage_account.archive`, `network:azurerm_storage_account.flow_logs` |
| `DET-001` | `defender:azurerm_security_center_subscription_pricing.this`, `root:module.defender` |
| `DET-002` | `defender:azurerm_security_center_subscription_pricing.this` |
| `DET-003` | `defender:azurerm_security_center_subscription_pricing.this` |
| `DET-004` | `defender:azurerm_security_center_contact.this` |
| `DET-005` | `defender:azurerm_security_center_auto_provisioning.this` |
| `DET-006` | `defender:azurerm_security_center_workspace.this` |
| `DET-007` | `defender:azurerm_security_center_automation.to_log_analytics` |
| `DET-008` | `defender:azurerm_security_center_automation.to_event_hub` |
| `DET-009` | `defender:azurerm_security_center_assessment_policy.worm_lock` |
| `DET-010` | `defender:azurerm_security_center_setting.mcas`, `defender:azurerm_security_center_setting.wdatp` |
| `DET-011` | `logging:azurerm_monitor_activity_log_alert.control_plane` |
| `DET-012` | `logging:azurerm_monitor_action_group.security` |
| `ENC-001` | `encryption:azurerm_key_vault.core`, `root:module.encryption` |
| `ENC-002` | `encryption:azurerm_key_vault_key.cmk` |
| `ENC-003` | `encryption:azurerm_key_vault_key.cmk` |
| `ENC-004` | `encryption:azurerm_disk_encryption_set.this` |
| `ENC-005` | `logging:azurerm_storage_account.archive` |
| `ENC-006` | `logging:azurerm_storage_account.archive`, `network:azurerm_storage_account.flow_logs` |
| `IAM-001` | `policy:azurerm_user_assigned_identity.remediation` |
| `IAM-002` | `policy:azurerm_role_assignment.remediation_contributor_mg`, `policy:azurerm_role_assignment.remediation_contributor_sub` |
| `IAM-003` | `policy:azurerm_role_assignment.remediation_security_admin_mg`, `policy:azurerm_role_assignment.remediation_security_admin_sub` |
| `IAM-004` | `policy:azurerm_role_assignment.remediation_monitoring_mg`, `policy:azurerm_role_assignment.remediation_monitoring_sub` |
| `IAM-005` | `root:azurerm_role_assignment.assessor_security_reader` |
| `IAM-006` | `encryption:azurerm_key_vault.core` |
| `IAM-007` | `encryption:azurerm_user_assigned_identity.cmk`, `encryption:azurerm_role_assignment.cmk_encryption_user`, `encryption:azurerm_role_assignment.des_encryption_user` |
| `IAM-008` | `encryption:azurerm_role_assignment.deployer_crypto_officer`, `encryption:data.azurerm_client_config.current` |
| `LOG-001` | `logging:azurerm_log_analytics_workspace.core`, `root:module.logging` |
| `LOG-002` | `logging:azurerm_log_analytics_workspace.core` |
| `LOG-003` | `logging:azurerm_monitor_diagnostic_setting.activity_log` |
| `LOG-004` | `logging:azurerm_monitor_diagnostic_setting.activity_log_eventhub` |
| `LOG-005` | `logging:azurerm_policy_definition.diagnostics` |
| `LOG-006` | `logging:azurerm_policy_set_definition.diagnostics`, `logging:azurerm_management_group_policy_assignment.diagnostics`, `logging:azurerm_subscription_policy_assignment.diagnostics` |
| `LOG-007` | `logging:azurerm_monitor_diagnostic_setting.key_vault` |
| `LOG-008` | `logging:azurerm_monitor_diagnostic_setting.archive_account` |
| `LOG-009` | `logging:azurerm_log_analytics_workspace.core` |
| `MG-001` | `management-groups:azurerm_management_group.root` |
| `MG-002` | `management-groups:azurerm_management_group.platform` |
| `MG-003` | `management-groups:azurerm_management_group.landing_zones`, `management-groups:azurerm_management_group.prod`, `management-groups:azurerm_management_group.nonprod` |
| `MG-004` | `management-groups:azurerm_management_group.sandbox` |
| `MG-005` | `management-groups:azurerm_management_group.decommissioned` |
| `MG-006` | `management-groups:azurerm_management_group_subscription_association.this` |
| `NET-001` | `network:azurerm_network_security_group.baseline`, `network:azurerm_subnet_network_security_group_association.workload`, `root:module.network` |
| `NET-002` | `network:azurerm_network_security_rule.deny_internet_management` |
| `NET-003` | `network:azurerm_network_security_rule.deny_all_inbound`, `network:azurerm_network_security_rule.allow_vnet_inbound` |
| `NET-004` | `network:azurerm_network_security_rule.deny_internet_egress` |
| `NET-005` | `network:azurerm_network_watcher.this` |
| `NET-006` | `network:azurerm_network_watcher_flow_log.baseline`, `network:azurerm_storage_account.flow_logs` |
| `NET-007` | `network:azurerm_private_endpoint.key_vault`, `network:azurerm_private_endpoint.archive_blob` |
| `NET-008` | `network:azurerm_private_dns_zone.this`, `network:azurerm_private_dns_zone_virtual_network_link.this` |
| `NET-009` | `network:azurerm_subnet.private_endpoints`, `network:azurerm_virtual_network.platform`, `network:azurerm_subnet.workload`, `network:azurerm_subnet_network_security_group_association.private_endpoints` |
| `NET-010` | `network:azurerm_network_ddos_protection_plan.this` |
| `NET-011` | `network:azurerm_monitor_diagnostic_setting.nsg` |
| `POL-001` | `policy:azurerm_management_group_policy_assignment.regulatory`, `root:module.policy` |
| `POL-002` | `policy:azurerm_subscription_policy_assignment.regulatory` |
| `POL-003` | `policy:azurerm_management_group_policy_assignment.regulatory`, `policy:azurerm_subscription_policy_assignment.regulatory` |
| `POL-004` | `policy:azurerm_management_group_policy_assignment.regulatory`, `policy:azurerm_subscription_policy_assignment.regulatory` |
| `POL-005` | `policy:azurerm_management_group_policy_assignment.regulatory` |
| `POL-006` | `policy:azurerm_policy_definition.allowed_locations` |
| `POL-007` | `policy:azurerm_policy_definition.allowed_vm_skus` |
| `POL-008` | `policy:azurerm_policy_definition.required_tags` |
| `POL-009` | `policy:azurerm_policy_definition.min_tls_version` |
| `POL-010` | `policy:azurerm_policy_definition.deny_public_blob` |
| `POL-011` | `policy:azurerm_policy_definition.deny_public_ip_nic` |
| `POL-012` | `policy:azurerm_policy_set_definition.custom_guardrails`, `policy:azurerm_management_group_policy_assignment.custom_guardrails`, `policy:azurerm_subscription_policy_assignment.custom_guardrails` |
| `POL-013` | `policy:azurerm_policy_set_definition.custom_guardrails` |
| `POL-014` | `policy:azurerm_management_group_policy_exemption.this`, `policy:azurerm_subscription_policy_exemption.this`, `policy:azurerm_resource_policy_exemption.this` |

## Reverse index (framework control -> repo control)

### FedRAMP Rev 5 (Moderate / High)

| Framework control | Implemented by |
|---|---|
| AC-2 | `IAM-001`, `IAM-005` |
| AC-3 | `DAT-005`, `DAT-006`, `DAT-008`, `IAM-006`, `MG-001`, `POL-010` |
| AC-4 | `POL-006` |
| AC-6 | `IAM-001`, `IAM-002`, `IAM-003`, `IAM-004`, `IAM-006`, `IAM-007`, `IAM-008` |
| AC-17 | `NET-002` |
| AC-22 | `POL-010` |
| AU-2 | `LOG-001`, `LOG-003`, `LOG-005`, `LOG-007`, `NET-006`, `NET-011` |
| AU-3 | `LOG-001`, `LOG-003` |
| AU-4 | `DAT-007`, `LOG-009` |
| AU-5 | `LOG-009` |
| AU-6 | `DET-006`, `DET-011`, `LOG-001`, `LOG-007` |
| AU-9 | `DAT-001`, `DAT-002`, `DET-008`, `DET-009`, `LOG-004`, `LOG-008` |
| AU-11 | `DAT-001`, `DAT-007`, `DET-007`, `LOG-002` |
| AU-12 | `IAM-004`, `LOG-003`, `LOG-005`, `LOG-006`, `NET-005`, `NET-006` |
| CA-2 | `IAM-005`, `POL-001`, `POL-002`, `POL-003` |
| CA-3 | `MG-004` |
| CA-5 | `POL-014` |
| CA-7 | `DET-007`, `POL-001`, `POL-002`, `POL-003`, `POL-005` |
| CM-2 | `MG-001`, `MG-002`, `MG-003`, `MG-006` |
| CM-3 | `DET-011`, `NET-011`, `POL-013` |
| CM-4 | `MG-003`, `POL-013` |
| CM-5 | `IAM-008`, `MG-002` |
| CM-6 | `LOG-006`, `POL-001`, `POL-005`, `POL-012` |
| CM-7 | `POL-007`, `POL-012` |
| CM-8 | `MG-006`, `POL-008` |
| CP-9 | `DAT-003`, `DAT-004`, `ENC-001` |
| CP-10 | `DAT-004` |
| IA-2 | `DAT-005` |
| IR-4 | `DET-008` |
| IR-6 | `DET-004`, `DET-012` |
| MP-6 | `ENC-005`, `MG-005` |
| RA-2 | `DET-003` |
| RA-3 | `POL-014` |
| RA-5 | `DET-001`, `DET-002` |
| SA-9 | `MG-004` |
| SC-5 | `NET-010` |
| SC-7 | `DAT-008`, `MG-002`, `MG-003`, `NET-001`, `NET-002`, `NET-003`, `NET-004`, `NET-007`, `NET-008`, `NET-009`, `POL-006`, `POL-011` |
| SC-8 | `POL-009` |
| SC-12 | `DAT-006`, `ENC-001`, `ENC-002`, `ENC-003`, `IAM-007` |
| SC-13 | `ENC-002`, `POL-009` |
| SC-20 | `NET-008` |
| SC-28 | `ENC-002`, `ENC-004`, `ENC-005`, `ENC-006` |
| SI-3 | `DET-003`, `DET-010` |
| SI-4 | `DET-001`, `DET-004`, `DET-005`, `DET-010`, `DET-011`, `NET-005`, `NET-006` |
| SI-7 | `DET-002` |
| SI-12 | `DAT-002`, `DAT-003` |

### NIST SP 800-53 Rev 5

| Framework control | Implemented by |
|---|---|
| AC-2 | `IAM-001`, `IAM-005` |
| AC-2(4) | `DET-011` |
| AC-2(7) | `IAM-001` |
| AC-3 | `DAT-005`, `DAT-006`, `DAT-008`, `IAM-006`, `MG-001`, `POL-010` |
| AC-4 | `NET-001`, `NET-004`, `POL-006` |
| AC-6 | `IAM-001`, `IAM-002`, `IAM-003`, `IAM-006` |
| AC-6(1) | `IAM-002`, `IAM-003`, `IAM-004`, `IAM-005`, `IAM-007`, `IAM-008` |
| AC-6(5) | `IAM-002` |
| AC-17 | `NET-002` |
| AC-17(1) | `NET-002` |
| AC-22 | `POL-010` |
| AU-2 | `LOG-001`, `LOG-003`, `LOG-005`, `LOG-007`, `NET-006`, `NET-011` |
| AU-3 | `LOG-001`, `LOG-003` |
| AU-4 | `DAT-007`, `LOG-002`, `LOG-009` |
| AU-5 | `LOG-009` |
| AU-6 | `DET-006`, `IAM-005`, `IAM-006`, `LOG-001`, `LOG-007` |
| AU-6(1) | `DET-011`, `DET-012` |
| AU-6(3) | `DAT-002`, `DET-006`, `DET-007`, `LOG-008` |
| AU-9 | `DAT-001`, `DAT-002`, `DET-009`, `LOG-004`, `LOG-008` |
| AU-9(2) | `DET-008`, `LOG-004` |
| AU-9(3) | `DAT-001`, `DET-009` |
| AU-11 | `DAT-001`, `DAT-007`, `DET-007`, `LOG-002` |
| AU-12 | `IAM-004`, `LOG-001`, `LOG-003`, `LOG-005`, `LOG-006`, `NET-005`, `NET-006` |
| CA-2 | `IAM-005`, `POL-001`, `POL-002`, `POL-003`, `POL-004` |
| CA-3 | `MG-004` |
| CA-5 | `POL-014` |
| CA-7 | `DET-001`, `DET-007`, `POL-001`, `POL-002`, `POL-003`, `POL-004`, `POL-005` |
| CM-2 | `MG-001`, `MG-002`, `MG-003`, `MG-006` |
| CM-3 | `DET-011`, `NET-011`, `POL-013`, `POL-014` |
| CM-4 | `MG-003`, `POL-013` |
| CM-5 | `IAM-008`, `MG-002` |
| CM-6 | `LOG-005`, `LOG-006`, `POL-001`, `POL-005`, `POL-012` |
| CM-7 | `POL-007`, `POL-012` |
| CM-8 | `MG-005`, `MG-006`, `POL-008` |
| CP-6 | `DAT-004` |
| CP-9 | `DAT-003`, `DAT-004`, `ENC-001` |
| CP-10 | `DAT-004` |
| IA-2 | `DAT-005` |
| IA-5 | `DAT-005`, `DAT-006` |
| IR-4 | `DET-008` |
| IR-6 | `DET-004`, `DET-012` |
| IR-6(1) | `DET-004` |
| MP-6 | `ENC-005`, `MG-005` |
| PL-2 | `MG-004` |
| PM-5 | `MG-001`, `POL-008` |
| PM-31 | `POL-001`, `POL-003` |
| RA-2 | `DET-003`, `POL-008` |
| RA-3 | `POL-014` |
| RA-5 | `DET-001`, `DET-002` |
| SA-9 | `MG-004`, `POL-006` |
| SA-11 | `POL-013` |
| SA-22 | `POL-007` |
| SC-5 | `NET-010` |
| SC-5(1) | `NET-010` |
| SC-7 | `DAT-008`, `MG-002`, `MG-003`, `NET-001`, `NET-002`, `NET-003`, `NET-007`, `NET-009`, `NET-011`, `POL-006`, `POL-011` |
| SC-7(3) | `NET-007`, `NET-008`, `NET-009` |
| SC-7(4) | `NET-004`, `POL-011` |
| SC-7(5) | `DAT-008`, `NET-003`, `NET-004` |
| SC-8 | `POL-009` |
| SC-8(1) | `POL-009` |
| SC-12 | `DAT-006`, `ENC-001`, `ENC-002`, `ENC-003`, `ENC-005`, `IAM-007`, `LOG-007` |
| SC-12(1) | `ENC-001`, `ENC-003` |
| SC-13 | `ENC-002`, `POL-009` |
| SC-20 | `NET-008` |
| SC-21 | `NET-008` |
| SC-28 | `ENC-002`, `ENC-004`, `ENC-006` |
| SC-28(1) | `ENC-002`, `ENC-004`, `ENC-005`, `ENC-006` |
| SI-3 | `DET-003`, `DET-010` |
| SI-4 | `DET-001`, `DET-003`, `DET-005`, `DET-008`, `DET-010` |
| SI-4(2) | `DET-005` |
| SI-4(4) | `NET-005`, `NET-006` |
| SI-4(5) | `DET-004`, `DET-011` |
| SI-7 | `DET-002` |
| SI-7(1) | `DET-002` |
| SI-12 | `DAT-002`, `DAT-003` |
| SR-12 | `MG-005` |

### CIS Microsoft Azure Foundations Benchmark

| Framework control | Implemented by |
|---|---|
| 1 | `IAM-001`, `IAM-002`, `IAM-003`, `IAM-005`, `MG-001`, `MG-002`, `MG-003`, `MG-004`, `MG-006`, `POL-004` |
| 2 | `DET-004`, `DET-005`, `DET-006`, `DET-007`, `DET-010`, `POL-001`, `POL-002`, `POL-004`, `POL-005` |
| 2.1 | `DET-001`, `DET-002`, `DET-003` |
| 3 | `DAT-001`, `DAT-002`, `DAT-003`, `DAT-004`, `DAT-005`, `DAT-008`, `DET-009`, `ENC-005`, `POL-004` |
| 3.2 | `ENC-006` |
| 3.3 | `DAT-006` |
| 3.7 | `POL-010` |
| 3.12 | `POL-009` |
| 4 | `POL-004` |
| 5 | `POL-004` |
| 5.1 | `IAM-004`, `LOG-001`, `LOG-002`, `LOG-003`, `LOG-004`, `LOG-005`, `LOG-006`, `LOG-008`, `NET-011` |
| 5.2 | `DET-011`, `DET-012` |
| 6 | `NET-001`, `NET-003`, `NET-004`, `NET-008`, `NET-009`, `NET-010`, `POL-004`, `POL-011` |
| 6.1 | `NET-002` |
| 6.2 | `NET-002` |
| 6.5 | `NET-005` |
| 6.6 | `NET-006` |
| 7 | `ENC-004`, `POL-004`, `POL-007` |
| 8 | `DAT-008`, `ENC-001`, `ENC-002`, `IAM-006`, `IAM-007`, `IAM-008`, `POL-004` |
| 8.1 | `ENC-003` |
| 8.5 | `LOG-007` |
| 8.6 | `NET-007` |
| 9 | `POL-004` |
| 10 | `POL-006`, `POL-008`, `POL-012` |

## Caveats and limitations

- **`DAT-001`** - Created in Unlocked state. Unlocked means an Owner can still shorten or remove it, and an assessor will treat that as a finding. Locking is irreversible for the life of the account -- not even Microsoft can undo it -- so it is a documented manual step, not something a first apply does to you.
- **`DAT-002`** - Versioning is a prerequisite for account-level immutability. The change feed is an ordered, durable log of every blob mutation -- the audit trail of the audit archive itself.
- **`DAT-003`** - 30 days at Moderate, 90 at High.
- **`DAT-004`** - GRS at Moderate, RAGRS at High so the secondary copy is readable during a regional outage rather than only after a failover is declared.
- **`DAT-005`** - Storage account keys are bearer credentials that cannot be scoped, rotated per-principal, or attributed to a human in the audit log. The flow log sink is a documented exception -- Network Watcher delivery requires shared key -- and the Conftest policy encodes that exception by tag, not by name.
- **`DAT-006`** - A long-lived SAS is an unrevocable credential that no directory sees.
- **`DAT-007`** - Deliberately has no delete action: the WORM policy owns the lifetime. A lifecycle delete racing an immutability policy produces a permanently failing rule and a misleading 'policy applied' status.
- **`DAT-008`** - The AzureServices bypass is required for Log Analytics and Defender continuous export to reach the archive at all, and for the disk encryption set to unwrap its key. It is a real widening of the boundary and is called out rather than buried.
- **`DET-001`** - Nine plans, each metered per resource per month, each defaulting to false. Enabling all of them across a real estate is a four-to-five figure monthly bill.
- **`DET-002`** - P1 at Moderate is agentless posture only. P2 at High adds agent-based vulnerability assessment and file integrity monitoring, which is what RA-5 and SI-7 actually ask for.
- **`DET-003`** - Metered per GB scanned. Off at Moderate because the per-GB charge on a high-throughput data lake is substantial and RA-2 lets you make that call from the data classification.
- **`DET-004`** - An alert nobody is paged for is a log entry.
- **`DET-005`** - Covers the legacy Log Analytics agent setting. Microsoft has retired MMA auto-provisioning in favour of the Azure Monitor Agent delivered by policy (LOG-005/006); both exist here because tenants are mid-migration for a long time.
- **`DET-006`** - Without co-location, the hunting query joining 'suspicious sign-in' to 'role assignment created' to 'storage firewall opened' cannot be written.
- **`DET-007`** - The Defender portal keeps findings for a rolling window only. 'Show me the secure score trend for the last six months' needs a table, not a screenshot.
- **`DET-008`** - Requires an Event Hub resource ID and a send-only connection string, supplied as a sensitive variable. No credential is stored in this repository.
- **`DET-009`** - Microsoft ships no assessment for 'the immutability policy exists but is Unlocked', which is exactly the state a first Terraform apply leaves you in.
- **`DET-010`** - Each integration is a data-sharing decision. Declaring it in code beats leaving it at whatever the subscription defaulted to years ago.
- **`DET-011`** - Eight alerts: policy assignment write/delete, NSG and NSG-rule write, Key Vault delete, Defender pricing change, role assignment write, diagnostic setting delete. These are the operations an attacker performs to become persistent or invisible.
- **`DET-012`** - An empty recipient list is a valid deployment and an invalid control: the alerts still fire and remain queryable, but nothing is pushed to anyone.
- **`ENC-001`** - Purge protection cannot be turned off once enabled -- that is the point. Without it a compromised Owner can delete and purge the vault inside the soft-delete window, permanently destroying every CMK and every volume they protect.
- **`ENC-002`** - RSA-HSM on a Premium vault: FIPS 140-2 Level 3. Separate keys for storage, disks and SQL so that rotating or destroying one does not take the others offline.
- **`ENC-003`** - P365D at Moderate, P180D at High, with automatic rotation rather than a documented manual procedure. A manual rotation procedure is a procedure that stops happening in month 14.
- **`ENC-004`** - Moderate uses EncryptionAtRestWithCustomerKey; High uses EncryptionAtRestWithPlatformAndCustomerKeys -- two independent layers. Attaching the set to disks is the workload team's job; this module publishes the ID.
- **`ENC-005`** - You cannot shred a disk you do not own. Destroying the CMK is the sanitisation path that makes MP-6 achievable in a cloud.
- **`IAM-001`** - User-assigned rather than system-assigned: a system-assigned identity is recreated on every re-assignment, orphaning its role assignments and silently breaking remediation.
- **`IAM-002`** - Honest limitation: Microsoft's own FedRAMP and NIST initiatives contain remediation tasks that require Contributor. The mitigations are a non-interactive identity and a scope confined to the baseline MG or subscription. If your assessor will not accept Contributor here, run with enforcement DoNotEnforce and remediate through change control instead.
- **`IAM-005`** - Security Reader rather than Reader: it exposes findings, compliance state and secure score without granting data-plane read across the estate.
- **`IAM-006`** - Access policies are a parallel authorization system invisible to `az role assignment list` and to PIM, which means AC-2 and AC-6 access reviews cannot see them at all.
- **`LOG-001`** - Billable by ingestion volume and retention. This is usually the largest recurring line item in the baseline.
- **`LOG-002`** - 365 days interactive at Moderate, 730 at High, with the WORM archive carrying the multi-year tail. 730 days is the Log Analytics interactive maximum -- anything longer must live in the archive.
- **`LOG-003`** - The platform retains the Activity Log for 90 days regardless. 90 days is shorter than the dwell time of most real intrusions, which is why this exists.
- **`LOG-004`** - Requires an existing Event Hub namespace. Off by default. Without this, an attacker with Owner on the subscription can eventually reach every copy of their own tracks.
- **`LOG-005`** - Metrics are requested per resource type, because asking a provider that publishes none for AllMetrics makes the nested deployment fail and produces a permanently non-compliant resource.
- **`LOG-006`** - Pre-existing resources are only fixed once a remediation task is run: `az policy remediation create`. Terraform creates the policy, not the remediation run.
- **`LOG-007`** - Lives in the logging module rather than the encryption module: routing it from encryption would make encryption depend on logging while logging already depends on encryption for the CMK, which Terraform cannot resolve.
- **`LOG-008`** - An attempt to weaken the immutability policy shows up here. Auditing the audit store is not paranoia; it is the only way AU-9 is testable.
- **`LOG-009`** - A daily quota protects the bill by DROPPING audit records once hit, not by queuing them. Defaults to uncapped. The Conftest policy in policies/audit_retention.rego warns whenever a cap is set.
- **`MG-001`** - Deliberately not the tenant root group. Policy written at the tenant root applies to every future subscription including ones the platform team does not own, and cannot be scoped away afterwards.
- **`MG-003`** - The split is what makes a strict production deny-set politically survivable: engineering keeps a place to move fast, and it is not inside the authorization boundary's prod scope.
- **`MG-004`** - Naming out-of-boundary scope explicitly is what lets an assessor accept 'not in scope' instead of treating every subscription in the tenant as in scope.
- **`MG-006`** - Uses the association resource rather than the authoritative `subscription_ids` argument, which would silently evict any subscription Terraform does not know about.
- **`NET-002`** - Priority 100 so it wins over anything a workload team adds later. Covers 22, 3389, WinRM, and the four database ports that turn up exposed most often.
- **`NET-003`** - The explicit deny at priority 4096 out-ranks Azure's implicit AllowVnetInBound at 65000, so a companion allow rule at 3900 restates intra-VNet reachability above it -- without that, the baseline NSG would black-hole private endpoint traffic. Redundant with Azure's implicit rule at 65500 by design. An assessor reading the rule list sees the intent; a future engineer cannot out-prioritise a rule they cannot see.
- **`NET-004`** - Off by default. Turning it on without a firewall or private-endpoint path first breaks agent enrolment, Windows Update and Key Vault access -- and a baseline that bricks a tenant on first apply gets removed rather than fixed.
- **`NET-005`** - Azure auto-creates one per region in most tenants. Set enable_network_watcher = false to adopt the existing instance instead of colliding with it.
- **`NET-006`** - Version 2 flow logs for byte and packet counts. Traffic analytics is what makes them reviewable -- without it you have gigabytes of JSON nobody will open.
- **`NET-008`** - Zone suffixes differ between commercial and Gov clouds. Getting this wrong makes clients resolve the public name to a public IP -- the private endpoint becomes an unused NIC and traffic quietly keeps traversing the internet.
- **`NET-009`** - The historical default disabled NSG evaluation on private endpoint traffic, which is a common and invisible blind spot.
- **`NET-010`** - Roughly USD 2,900/month per tenant regardless of how many VNets use it. The single most expensive switch in this repository, and off by default.
- **`POL-001`** - Which initiative is assigned -- FedRAMP Moderate or FedRAMP High -- is selected by var.fedramp_baseline. Only one is ever assigned; assigning both produces duplicated DINE remediations and a dashboard that double-counts findings.
- **`POL-002`** - Lets the whole baseline be evaluated by someone who does not own the tenant root group. Loses inheritance to future subscriptions.
- **`POL-003`** - Rev 5 and Rev 4 are different built-in initiatives. The GUID for Rev 4 (cf25b9c1-...) is documented in initiatives.tf specifically so it is not mistaken for Rev 5.
- **`POL-004`** - NOT ASSIGNED BY DEFAULT. This repo ships no verified policy set definition GUID for the v3.0.0 built-in, and guessing one would assign the wrong benchmark version -- a green dashboard against the wrong control set is worse than no dashboard. Supply the GUID via var.builtin_initiative_id_overrides after confirming it with `az policy set-definition list`. The `initiatives_requiring_guid_verification` output reports the gap on every plan.
- **`POL-005`** - Often already present as the legacy 'ASC Default' subscription assignment. Re-assigning it at MG scope makes it explicit, versioned and visible in code.
- **`POL-006`** - A FedRAMP boundary is geographic. A resource created outside it is outside the boundary the moment it exists, and no detective control puts the data back.
- **`POL-008`** - Uses the Azure Policy `count` expression over a parameterised tag list, so the required tag set is configuration rather than six copy-pasted policies.
- **`POL-009`** - The built-in equivalents ship as Audit in several initiatives. A Deny is what stops TLS 1.0 being re-enabled by an engineer chasing a legacy client.
- **`POL-011`** - A NIC-attached public IP is an uninspected path around every hub firewall and NVA in the architecture.
- **`POL-012`** - One assignment means one thing to exempt from, one compliance row to report, and one parameter set to tune -- instead of six independent assignments that drift apart.
- **`POL-013`** - Every custom definition takes an `effect` parameter. A baseline that goes straight to Deny against a live tenant gets deleted by someone with Owner within a week.
- **`POL-014`** - The variable schema forces a justification and an expiry. Azure stops honouring the exemption at the expiry date, so an unrenewed waiver fails closed instead of lasting forever.

## Framework notes

- FedRAMP Rev 5 is a profile of NIST SP 800-53 Rev 5, so the control identifiers in the two columns are largely the same by construction. The FedRAMP column is populated only where the control appears in the Moderate or High baseline; a NIST-only entry means the control is in the catalog but not in the FedRAMP baseline this repo targets.
- CIS references are given at section granularity (for example `6.1`, `3.12`) rather than at full recommendation granularity. Sub-numbering shifted between CIS Azure Foundations v2.0.0 and v3.0.0, and citing a precise recommendation number I have not re-verified against the published v3.0.0 PDF would be worse than citing the section. Verify against the benchmark before quoting these in an assessment package.
- The CIS Microsoft Azure Foundations v3.0.0 built-in initiative is NOT assigned by default: this repo does not ship a verified policy set definition GUID for it. See POL-004 and the `initiatives_requiring_guid_verification` output. Until you supply the GUID, CIS coverage in this repo comes from the custom guardrail policies only.
- Entra ID controls -- Conditional Access, PIM, access reviews, authentication methods -- are deliberately absent. They are a separate control plane with a separate provider and separate blast radius, and they live in the author's `az-iam-conditional-pim` repo. The IAM- controls here cover Azure RBAC role assignments only.
