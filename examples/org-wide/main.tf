# ---------------------------------------------------------------------------
# Org-wide, FedRAMP High posture.
#
# This is the shape the repo is designed around: you own an intermediate
# management group, Microsoft.Management is registered in the tenant, and you
# have Owner (or Contributor + User Access Administrator) at that MG scope.
#
# Everything metered is switched ON here. Read the Cost section of the README
# before copying this file -- across a real estate this is a four-figure monthly
# bill before a single workload runs.
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

# The azurerm provider is configured inside the baseline module (see
# terraform/providers.tf) because several feature flags -- Key Vault purge
# behaviour in particular -- are themselves controls and should not be a caller
# decision.

module "baseline" {
  source = "../../terraform"

  # Placeholders. There are no real tenant identifiers anywhere in this repo.
  subscription_id = "00000000-0000-0000-0000-000000000000"
  tenant_id       = "00000000-0000-0000-0000-000000000000"

  fedramp_baseline = "high"
  deployment_scope = "management_group"

  name_prefix        = "govhigh"
  system_id          = "SYS-HIGH-0001"
  primary_location   = "usgovvirginia"
  secondary_location = "usgovtexas"
  azure_environment  = "usgovernment"

  root_management_group_display_name = "FedRAMP High Boundary"

  # Placement of the subscriptions inside the boundary. Sandbox is deliberately
  # a sibling of landing-zones, not a child, so that out-of-boundary work does
  # not inherit in-boundary policy and confuse the compliance dashboard.
  subscription_associations = {
    platform = ["00000000-0000-0000-0000-000000000000"]
    prod     = ["00000000-0000-0000-0000-000000000000"]
    nonprod  = ["00000000-0000-0000-0000-000000000000"]
  }

  # SC-7 / AC-4: geo-fenced to the Gov regions.
  allowed_locations = ["usgovvirginia", "usgovtexas"]

  # CM-7: a deliberately short list. Adding to it is a change request.
  allowed_vm_sku_sizes = [
    "Standard_D2s_v5",
    "Standard_D4s_v5",
    "Standard_D8s_v5",
    "Standard_E4s_v5",
  ]

  required_tags = ["owner", "data-classification", "system-id", "poam-owner"]

  # Hard enforcement. This is the target state, not the first apply -- run once
  # with guardrail_effect = "Audit" against a live tenant before you get here.
  guardrail_effect              = "Deny"
  policy_assignment_enforcement = "Default"

  # CIS v3.0.0 ships without a verified GUID in this repo. Supply the real one
  # after confirming it:
  #   az policy set-definition list \
  #     --query "[?contains(displayName,'CIS Microsoft Azure Foundations Benchmark v3')].name" -o tsv
  # builtin_initiative_id_overrides = {
  #   cis_azure_v3_0_0 = "00000000-0000-0000-0000-000000000000"
  # }

  # ---- Detective controls. All metered. -----------------------------------
  enable_defender_for_cloud         = true
  enable_defender_servers           = true
  enable_defender_storage           = true
  enable_defender_sql               = true
  enable_defender_containers        = true
  enable_defender_key_vault         = true
  enable_defender_arm               = true
  enable_defender_app_services      = true
  enable_defender_open_source_db    = true
  enable_defender_continuous_export = true
  enable_defender_auto_provisioning = true

  # ---- Audit substrate ----------------------------------------------------
  enable_logging           = true
  enable_immutable_archive = true

  # ---- Boundary -----------------------------------------------------------
  enable_network           = true
  enable_nsg_flow_logs     = true
  enable_private_endpoints = true
  enable_ddos_protection   = true

  # SC-7(4)/(5) target state. Requires a firewall or private-endpoint egress
  # path to already exist -- see the module variable docs.
  deny_internet_egress = true

  # ---- Encryption ---------------------------------------------------------
  enable_encryption = true

  # ---- People -------------------------------------------------------------
  security_contact_emails   = ["soc@example.gov"]
  alert_notification_emails = ["soc@example.gov", "iso@example.gov"]

  # AC-2 / CA-2: read-only evidence access for the assessment team.
  assessor_principal_ids = []

  # CA-5: a worked exemption. Justification and expiry are required by the
  # variable schema, because an exemption without either is just a hole.
  policy_exemptions = {
    "legacy-tls-appliance" = {
      policy_assignment_key = "guardrails"
      scope_id              = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-legacy-vendor"
      category              = "Mitigated"
      justification         = "Vendor storage appliance pinned to TLS 1.1 pending EOL in Q3. Compensating control: TLS-terminating reverse proxy in front of the endpoint, no direct client access. Tracked as POA&M-0042."
      expires_on            = "2027-01-31T00:00:00Z"

      policy_definition_reference_ids = ["storageMinTls"]
    }
  }

  tags = {
    "cost-center" = "SEC-1000"
    "environment" = "production"
  }
}

output "baseline_summary" {
  description = "What this deployment actually enforces."
  value       = module.baseline.baseline_summary
}

output "initiatives_requiring_guid_verification" {
  description = "Non-empty means a framework is not being evaluated. Fix before claiming coverage."
  value       = module.baseline.initiatives_requiring_guid_verification
}

output "post_apply_manual_steps" {
  description = "What Terraform deliberately left for a human."
  value       = module.baseline.post_apply_manual_steps
}
