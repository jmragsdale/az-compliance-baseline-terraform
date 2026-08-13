# ---------------------------------------------------------------------------
# Single subscription, FedRAMP Moderate, near-zero cost.
#
# This is the shape you use when you do not own the tenant root group -- a
# contractor working inside someone else's tenant, a proof of concept, or a lab.
# Every Microsoft.Management resource is skipped; the same policy definitions and
# assignments land at subscription scope instead.
#
# Every metered service is OFF. The only recurring cost is Log Analytics
# ingestion, which for a quiet subscription's Activity Log is cents per day.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

module "baseline" {
  source = "../../terraform"

  subscription_id = "00000000-0000-0000-0000-000000000000"
  tenant_id       = "00000000-0000-0000-0000-000000000000"

  fedramp_baseline = "moderate"
  deployment_scope = "single_subscription"

  name_prefix        = "labmod"
  system_id          = "SYS-LAB-0001"
  primary_location   = "eastus"
  secondary_location = "westus"

  # Commercial cloud, not Gov -- this changes the private DNS zone suffixes.
  azure_environment = "public"
  allowed_locations = ["eastus", "westus", "eastus2"]

  # Audit, not Deny. In a shared subscription you rarely have the authority to
  # block other people's deployments, and a Deny you cannot defend gets your
  # assignment deleted. Report first; earn the Deny.
  guardrail_effect              = "Audit"
  policy_assignment_enforcement = "Default"

  required_tags = ["owner", "system-id"]

  # ---- Detective controls: all off. ---------------------------------------
  # Defender plans are billed per resource per month and this posture is meant
  # to cost nothing. The regulatory initiatives still evaluate and still populate
  # the compliance dashboard -- policy evaluation itself is free.
  enable_defender_for_cloud = false

  # ---- Audit substrate: on, but small. ------------------------------------
  enable_logging           = true
  enable_immutable_archive = true

  # AU-4 / AU-5 tradeoff made explicit: a 1 GB/day cap protects a lab budget and
  # WILL drop audit records if something starts logging heavily. Acceptable in a
  # lab, never acceptable in an authorization boundary.
  log_analytics_daily_quota_gb = 1

  # ---- Boundary: NSG and Network Watcher only. ----------------------------
  enable_network           = true
  enable_nsg_flow_logs     = false
  enable_private_endpoints = false
  enable_ddos_protection   = false
  deny_internet_egress     = false

  # ---- Encryption: on. Key Vault Premium is a few dollars a month. --------
  enable_encryption = true

  alert_notification_emails = ["lab-owner@example.com"]

  tags = {
    "cost-center" = "LAB-0001"
    "environment" = "sandbox"
  }
}

output "baseline_summary" {
  description = "What this deployment actually enforces."
  value       = module.baseline.baseline_summary
}

output "management_group_ids" {
  description = "Null here by design -- single_subscription mode creates no management groups."
  value       = module.baseline.management_group_ids
}

output "post_apply_manual_steps" {
  description = "What Terraform deliberately left for a human."
  value       = module.baseline.post_apply_manual_steps
}
