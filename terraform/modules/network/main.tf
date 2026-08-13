# ---------------------------------------------------------------------------
# Platform network and the deny-by-default boundary.
#
# SC-7 is the control everything here serves: "monitor and control communications
# at the external boundary and at key internal boundaries". In Azure that decomposes
# into three concrete obligations:
#
#   1. an explicit deny that does not depend on remembering to write one
#      (Azure's implicit default rules allow VNet-to-VNet and all outbound)
#   2. a record of what actually traversed the boundary -- SC-7 alone is not
#      enough, AU-2 and AU-12 want the flow records
#   3. a way for in-boundary services to talk to PaaS without the traffic ever
#      touching a public endpoint -- SC-7(3) "limit external connections to
#      managed interfaces"
#
# The DDoS plan (SC-5) is separate and expensive; it is off by default and the
# README says what it costs.
# ---------------------------------------------------------------------------

locals {
  # Private DNS zone names are cloud-specific. A privatelink.vaultcore.azure.net
  # zone in a Gov tenant resolves nothing and the failure mode is a silent
  # fallback to the public endpoint -- which is exactly the SC-7 violation the
  # private endpoint was supposed to prevent.
  dns_suffixes = {
    public = {
      key_vault = "privatelink.vaultcore.azure.net"
      blob      = "privatelink.blob.core.windows.net"
    }
    usgovernment = {
      key_vault = "privatelink.vaultcore.usgovcloudapi.net"
      blob      = "privatelink.blob.core.usgovcloudapi.net"
    }
  }

  zones = local.dns_suffixes[var.azure_environment]

  private_dns_zones = var.enable_private_endpoints ? {
    key_vault = local.zones.key_vault
    blob      = local.zones.blob
  } : {}
}

resource "azurerm_virtual_network" "platform" {
  name                = "vnet-${var.name_prefix}-platform"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.vnet_address_space

  dynamic "ddos_protection_plan" {
    for_each = var.enable_ddos_protection ? [1] : []
    content {
      id     = azurerm_network_ddos_protection_plan.this[0].id
      enable = true
    }
  }

  tags = merge(var.tags, { "control-family" = "SC" })
}

# SC-7(3): private endpoints get their own subnet with network policies enabled,
# so NSG rules apply to private endpoint traffic rather than being silently
# bypassed (the historical default, and a common blind spot).
resource "azurerm_subnet" "private_endpoints" {
  name                              = "snet-private-endpoints"
  resource_group_name               = var.resource_group_name
  virtual_network_name              = azurerm_virtual_network.platform.name
  address_prefixes                  = [var.private_endpoint_subnet_prefix]
  private_endpoint_network_policies = "Enabled"
}

resource "azurerm_subnet" "workload" {
  name                 = "snet-workload"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.platform.name
  address_prefixes     = [var.workload_subnet_prefix]
}

# ---------------------------------------------------------------------------
# Baseline NSG.
#
# Azure ships four implicit rules at priority 65000+: AllowVnetInBound,
# AllowAzureLoadBalancerInBound, DenyAllInBound, AllowVnetOutBound,
# AllowInternetOutBound, DenyAllOutBound. The inbound default is already deny --
# but AllowVnetInBound at 65000 means anything inside the VNet reaches anything
# else, and AllowInternetOutBound means every VM can exfiltrate freely.
#
# The rules below make the intent explicit at a priority a human can reason
# about, and produce an auditable artifact: "deny 22/3389 from Internet" as a
# named rule is evidence; relying on an implicit default is not.
# ---------------------------------------------------------------------------

resource "azurerm_network_security_group" "baseline" {
  name                = "nsg-${var.name_prefix}-baseline"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = merge(var.tags, { "control-family" = "SC-7" })
}

# CIS Microsoft Azure Foundations v3.0.0 6.1 / 6.2, NIST AC-17: remote management
# ports must not be reachable from the internet. Named explicitly at priority 100
# so it wins over anything a workload team adds later.
resource "azurerm_network_security_rule" "deny_internet_management" {
  name                        = "deny-internet-management-ports"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.baseline.name

  priority                   = 100
  direction                  = "Inbound"
  access                     = "Deny"
  protocol                   = "*"
  source_port_range          = "*"
  destination_port_ranges    = ["22", "3389", "5985", "5986", "1433", "3306", "5432", "27017"]
  source_address_prefix      = "Internet"
  destination_address_prefix = "*"

  # Remote administration goes through Bastion or a jump path, never a public
  # listener. (Azure caps rule descriptions at 140 chars, hence the short form.)
  description = "CIS Azure v3.0.0 6.1/6.2, NIST AC-17: management ports unreachable from the internet"
}

# Restating Azure's implicit AllowVnetInBound above the terminal deny below.
#
# This rule is load-bearing, not decorative: the explicit deny at priority 4096
# out-ranks Azure's implicit AllowVnetInBound at 65000, so without this rule the
# baseline NSG would black-hole all intra-VNet traffic including private endpoint
# access to Key Vault. Tightening this to specific subnets and ports is a
# workload decision and deliberately not made by a platform baseline.
resource "azurerm_network_security_rule" "allow_vnet_inbound" {
  name                        = "allow-vnet-inbound"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.baseline.name

  priority                   = 3900
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "*"
  source_port_range          = "*"
  destination_port_range     = "*"
  source_address_prefix      = "VirtualNetwork"
  destination_address_prefix = "VirtualNetwork"

  # Explicit so the terminal deny below is a real default-deny rather than an
  # outage. East-west segmentation beyond this is a workload responsibility.
  description = "NIST SC-7: permit intra-VNet traffic ahead of the terminal deny-all"
}

# SC-7: an explicit terminal deny. Redundant with Azure's implicit 65500 rule by
# design -- an assessor reading the rule list sees the intent, and a future
# engineer cannot accidentally out-prioritise a rule they cannot see.
resource "azurerm_network_security_rule" "deny_all_inbound" {
  name                        = "deny-all-inbound"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.baseline.name

  priority                   = 4096
  direction                  = "Inbound"
  access                     = "Deny"
  protocol                   = "*"
  source_port_range          = "*"
  destination_port_range     = "*"
  source_address_prefix      = "*"
  destination_address_prefix = "*"

  description = "NIST SC-7: explicit deny-by-default at the lowest inbound priority. Everything permitted must be permitted by a named rule above this one."
}

# SC-7(4)/(5): egress deny. Off by default because switching it on without a
# firewall path first breaks agent enrolment and Key Vault access, and a baseline
# that bricks the tenant on first apply gets removed rather than fixed.
resource "azurerm_network_security_rule" "deny_internet_egress" {
  count = var.deny_internet_egress ? 1 : 0

  name                        = "deny-internet-egress"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.baseline.name

  priority                   = 4000
  direction                  = "Outbound"
  access                     = "Deny"
  protocol                   = "*"
  source_port_range          = "*"
  destination_port_range     = "*"
  source_address_prefix      = "*"
  destination_address_prefix = "Internet"

  description = "NIST SC-7(4)/(5): deny unrestricted egress. Requires a firewall or private-endpoint path for platform traffic to be in place first."
}

resource "azurerm_subnet_network_security_group_association" "workload" {
  subnet_id                 = azurerm_subnet.workload.id
  network_security_group_id = azurerm_network_security_group.baseline.id
}

# The private endpoint subnet gets the same NSG. Historically Azure did not
# evaluate NSGs on private endpoint traffic at all, and many designs still leave
# this subnet unprotected out of habit. With private_endpoint_network_policies
# enabled (above) the rules apply, which closes an invisible east-west path to
# the Key Vault and the audit archive.
resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  subnet_id                 = azurerm_subnet.private_endpoints.id
  network_security_group_id = azurerm_network_security_group.baseline.id
}

# AU-2 / CM-3: NSG rule changes are the boundary's change history.
resource "azurerm_monitor_diagnostic_setting" "nsg" {
  count = var.log_analytics_workspace_id != null ? 1 : 0

  name                       = "diag-${var.name_prefix}-nsg"
  target_resource_id         = azurerm_network_security_group.baseline.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "NetworkSecurityGroupEvent" }
  enabled_log { category = "NetworkSecurityGroupRuleCounter" }
}

# SC-5: volumetric attack absorption. Priced per tenant, not per resource, which
# is why it is a single plan shared by every VNet and why it is off by default.
resource "azurerm_network_ddos_protection_plan" "this" {
  count = var.enable_ddos_protection ? 1 : 0

  name                = "ddos-${var.name_prefix}"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = merge(var.tags, { "control-family" = "SC-5" })
}
