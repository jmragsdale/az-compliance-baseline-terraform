# Changelog - az-compliance-baseline-terraform

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-08-13

### Added

- Initial control baseline: preventive guardrails, detective/CSPM configuration,
  centralized audit logging, encryption, and network posture modules.
- `controls/controls.yaml` as the single machine-readable source of truth, with
  `controls/render.py` generating `CONTROLS.md` and verifying every claimed
  control resolves to a real Terraform address.
- CI: `terraform fmt`/`validate`, tflint, Checkov, Trivy, Conftest, gitleaks and
  control-matrix integrity checks.
- `examples/org-wide/` and `examples/single-subscription/` deployment shapes.
- FedRAMP baseline selectable between Moderate and High via variable.

### Azure specifics

- Management group hierarchy: intermediate root, `platform`, `landing-zones`
  (`prod` / `nonprod`), `sandbox`, `decommissioned`, with additive subscription
  association. Entirely gated by `deployment_scope`.
- Built-in regulatory initiative assignment for FedRAMP Moderate/High (selected by
  `fedramp_baseline`), NIST SP 800-53 Rev 5 and the Microsoft Cloud Security
  Benchmark. CIS Azure Foundations v3.0.0 ships **unassigned** pending GUID
  verification, reported by the `initiatives_requiring_guid_verification` output.
- Six custom `Deny` policy definitions packaged as one initiative: approved
  regions, approved VM SKUs, required inventory tags, storage TLS floor,
  anonymous blob access, NIC-attached public IPs.
- deployIfNotExists diagnostic-settings initiative across five resource types,
  sharing one user-assigned remediation identity with scoped role assignments.
- Documented, expiring policy exemptions at management group, subscription and
  resource scope.
- Immutable (WORM) audit archive with blob versioning, change feed, lifecycle
  tiering and a customer-managed key. Created `Unlocked` by design.
- Key Vault Premium in RBAC mode with purge protection, RSA-HSM customer-managed
  keys per data domain, automatic rotation and a disk encryption set that uses
  platform+customer double encryption at the High baseline.
- Nine Defender for Cloud plans, security contacts, auto-provisioning and
  continuous export to Log Analytics and Event Hub — each behind its own
  `enable_*` switch, all defaulting to `false`.
- Deny-by-default NSG with a companion intra-VNet allow rule, Network Watcher,
  version 2 flow logs with traffic analytics, private endpoints with
  cloud-correct private DNS zones, and an optional DDoS Network Protection plan.
- Eight Activity Log alerts on the control-plane operations that weaken the
  baseline itself.
- `scripts/export-evidence.sh`: read-only `az` CLI evidence bundle with a
  manifest that records the sections it could not read.
