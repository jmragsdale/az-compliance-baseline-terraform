# ---------------------------------------------------------------------------
# Custom policy definitions.
#
# These exist because the built-in regulatory initiatives are almost entirely
# *audit* effects. They tell you after the fact that something non-compliant was
# created. FedRAMP Rev 5 CM-7 (least functionality), CM-6 (configuration
# settings) and SC-7 (boundary protection) are not satisfied by knowing; they are
# satisfied by the request failing. Each definition below is a hard Deny that the
# built-ins do not give you, or give you only as Audit.
#
# Every definition is parameterised with an `effect` so a tenant can stage the
# rollout: Audit -> observe the blast radius -> Deny.
# ---------------------------------------------------------------------------

locals {
  # Definitions live at MG scope when we own an MG, otherwise at subscription
  # scope (implicit from the provider). A definition scoped to a subscription
  # cannot be assigned at MG scope, which is why this tracks deployment_scope.
  definition_mg_id = local.mg_scope ? var.management_group_id : null

  effect_parameter = {
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
      metadata = {
        displayName = "Effect"
        description = "Audit to stage the rollout, Deny to enforce, Disabled to switch the control off without deleting the assignment."
      }
    }
  }
}

# --- SC-7 / AC-4 : data residency -------------------------------------------
# A FedRAMP authorization boundary is geographic. A resource created in an
# unapproved region is outside the boundary the moment it exists, and no
# detective control puts that data back.
resource "azurerm_policy_definition" "allowed_locations" {
  name                = "${var.name_prefix}-allowed-locations"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deny resources outside approved regions"
  description         = "FedRAMP Rev 5 / NIST 800-53 Rev 5 SC-7, AC-4: the authorization boundary is geographic. Resources outside the approved region list are outside the boundary."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "General"
    version  = "1.0.0"
  })

  parameters = jsonencode(merge(local.effect_parameter, {
    allowedLocations = {
      type = "Array"
      metadata = {
        displayName = "Approved regions"
        description = "Regions inside the authorization boundary."
        strongType  = "location"
      }
    }
  }))

  policy_rule = jsonencode({
    # The "if" key is quoted deliberately. Unquoted, `if` is a bare HCL keyword
    # in object-key position and python-hcl2 (which Checkov and several other
    # scanners use) fails to parse the file at all -- silently, as a "parsing
    # error" rather than a finding. Terraform itself accepts either form.
    "if" = {
      allOf = [
        {
          field = "location"
          notIn = "[parameters('allowedLocations')]"
        },
        {
          # Global resources (Front Door, Traffic Manager, DNS) report
          # location "global" and are not region-bound.
          field     = "location"
          notEquals = "global"
        },
        {
          field     = "location"
          notEquals = "[resourcegroup().location]"
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })
}

# --- CM-7 : least functionality ---------------------------------------------
# Unbounded VM SKU choice is both a cost and a security problem: it is how
# GPU-class machines get stood up for crypto mining and how unsupported legacy
# SKUs without accelerated networking or confidential compute survive.
resource "azurerm_policy_definition" "allowed_vm_skus" {
  name                = "${var.name_prefix}-allowed-vm-skus"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deny virtual machines outside the approved SKU list"
  description         = "NIST 800-53 Rev 5 CM-7 least functionality: constrain compute to a reviewed SKU set. Also bounds the cost blast radius of a compromised deployment identity."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "Compute"
    version  = "1.0.0"
  })

  parameters = jsonencode(merge(local.effect_parameter, {
    allowedSkus = {
      type = "Array"
      metadata = {
        displayName = "Approved VM SKUs"
        description = "SKU names permitted inside the boundary."
      }
    }
  }))

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Compute/virtualMachines"
        },
        {
          field = "Microsoft.Compute/virtualMachines/sku.name"
          notIn = "[parameters('allowedSkus')]"
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })
}

# --- CM-8 : system component inventory --------------------------------------
# An assessor will ask "which system does this resource belong to and who owns
# it". If that is not answerable from a tag query, it is answerable only from
# tribal knowledge, and tribal knowledge is not evidence.
resource "azurerm_policy_definition" "required_tags" {
  name                = "${var.name_prefix}-required-tags"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deny resources missing required inventory tags"
  description         = "NIST 800-53 Rev 5 CM-8 system component inventory: ownership, data classification and system ID must be queryable, not tribal. Also underpins scoping evidence exports to one boundary."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "Tags"
    version  = "1.0.0"
  })

  parameters = jsonencode(merge(local.effect_parameter, {
    requiredTags = {
      type = "Array"
      metadata = {
        displayName = "Required tag names"
        description = "Tag names that must be present and non-empty."
      }
    }
  }))

  policy_rule = jsonencode({
    "if" = {
      count = {
        value = "[parameters('requiredTags')]"
        name  = "tagName"
        where = {
          anyOf = [
            {
              field  = "[concat('tags[', current('tagName'), ']')]"
              exists = "false"
            },
            {
              field  = "[concat('tags[', current('tagName'), ']')]"
              equals = ""
            }
          ]
        }
      }
      greater = 0
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })
}

# --- SC-8 / SC-13 : transmission confidentiality ----------------------------
# CIS Microsoft Azure Foundations v3.0.0 section 3 requires TLS 1.2 as the
# minimum on storage. The built-in for this ships as Audit in several
# initiatives; a Deny is what actually stops TLS 1.0 from being re-enabled by a
# well-meaning engineer chasing a legacy client.
resource "azurerm_policy_definition" "min_tls_version" {
  name                = "${var.name_prefix}-storage-min-tls"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deny storage accounts below the minimum TLS version"
  description         = "CIS Microsoft Azure Foundations v3.0.0 section 3 and NIST 800-53 Rev 5 SC-8(1)/SC-13: transmission confidentiality requires a FIPS-validated modern cipher suite negotiation floor."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "Storage"
    version  = "1.0.0"
  })

  parameters = jsonencode(merge(local.effect_parameter, {
    minimumTlsVersions = {
      type = "Array"
      metadata = {
        displayName = "Acceptable minimumTlsVersion values"
        description = "Storage accounts whose minimumTlsVersion is not in this list are non-compliant."
      }
      defaultValue = ["TLS1_2", "TLS1_3"]
    }
  }))

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field = "Microsoft.Storage/storageAccounts/minimumTlsVersion"
          notIn = "[parameters('minimumTlsVersions')]"
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })
}

# --- AC-3 / AC-22 : no anonymous data access --------------------------------
# Publicly readable blob containers are the single most common cause of "cloud
# data breach" headlines. Denying the account-level capability is stronger than
# auditing individual containers, because it removes the ability entirely.
resource "azurerm_policy_definition" "deny_public_blob" {
  name                = "${var.name_prefix}-deny-public-blob"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deny storage accounts that allow anonymous blob access"
  description         = "NIST 800-53 Rev 5 AC-3 access enforcement and AC-22 publicly accessible content. Removes the account-level capability rather than auditing container-by-container."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "Storage"
    version  = "1.0.0"
  })

  parameters = jsonencode(local.effect_parameter)

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field     = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess"
          notEquals = "false"
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })
}

# --- SC-7 : boundary protection ---------------------------------------------
# A public IP attached directly to a NIC bypasses every hub firewall, NVA and
# egress inspection point the architecture depends on. The boundary is only a
# boundary if there is no way around it.
resource "azurerm_policy_definition" "deny_public_ip_nic" {
  name                = "${var.name_prefix}-deny-public-ip-nic"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Deny network interfaces with a directly attached public IP"
  description         = "NIST 800-53 Rev 5 SC-7 boundary protection: workload traffic must traverse the inspected boundary. A NIC-attached public IP is an uninspected path around it."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "Network"
    version  = "1.0.0"
  })

  parameters = jsonencode(local.effect_parameter)

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Network/networkInterfaces"
        },
        {
          count = {
            field = "Microsoft.Network/networkInterfaces/ipConfigurations[*]"
            where = {
              field  = "Microsoft.Network/networkInterfaces/ipConfigurations[*].publicIPAddress.id"
              exists = "true"
            }
          }
          greater = 0
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
    }
  })
}

# ---------------------------------------------------------------------------
# One initiative wrapping all six, so there is a single assignment to exempt
# from, a single compliance row to report on, and one set of parameters to tune.
# ---------------------------------------------------------------------------
resource "azurerm_policy_set_definition" "custom_guardrails" {
  name                = "${var.name_prefix}-custom-guardrails"
  policy_type         = "Custom"
  display_name        = "Compliance baseline - preventive guardrails"
  description         = "The hard denials the built-in regulatory initiatives leave as audit-only: region fencing, SKU restriction, inventory tagging, TLS floor, anonymous blob access, and NIC-attached public IPs."
  management_group_id = local.definition_mg_id

  metadata = jsonencode({
    category = "Regulatory Compliance"
    version  = "1.0.0"
  })

  parameters = jsonencode({
    effect             = { type = "String", allowedValues = ["Audit", "Deny", "Disabled"], defaultValue = "Deny" }
    allowedLocations   = { type = "Array" }
    allowedSkus        = { type = "Array" }
    requiredTags       = { type = "Array" }
    minimumTlsVersions = { type = "Array", defaultValue = ["TLS1_2", "TLS1_3"] }
  })

  policy_definition_reference {
    reference_id         = "allowedLocations"
    policy_definition_id = azurerm_policy_definition.allowed_locations.id
    parameter_values = jsonencode({
      effect           = { value = "[parameters('effect')]" }
      allowedLocations = { value = "[parameters('allowedLocations')]" }
    })
  }

  policy_definition_reference {
    reference_id         = "allowedVmSkus"
    policy_definition_id = azurerm_policy_definition.allowed_vm_skus.id
    parameter_values = jsonencode({
      effect      = { value = "[parameters('effect')]" }
      allowedSkus = { value = "[parameters('allowedSkus')]" }
    })
  }

  policy_definition_reference {
    reference_id         = "requiredTags"
    policy_definition_id = azurerm_policy_definition.required_tags.id
    parameter_values = jsonencode({
      effect       = { value = "[parameters('effect')]" }
      requiredTags = { value = "[parameters('requiredTags')]" }
    })
  }

  policy_definition_reference {
    reference_id         = "storageMinTls"
    policy_definition_id = azurerm_policy_definition.min_tls_version.id
    parameter_values = jsonencode({
      effect             = { value = "[parameters('effect')]" }
      minimumTlsVersions = { value = "[parameters('minimumTlsVersions')]" }
    })
  }

  policy_definition_reference {
    reference_id         = "denyPublicBlob"
    policy_definition_id = azurerm_policy_definition.deny_public_blob.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('effect')]" }
    })
  }

  policy_definition_reference {
    reference_id         = "denyPublicIpNic"
    policy_definition_id = azurerm_policy_definition.deny_public_ip_nic.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('effect')]" }
    })
  }
}

locals {
  guardrail_parameters = jsonencode({
    effect             = { value = var.guardrail_effect }
    allowedLocations   = { value = var.allowed_locations }
    allowedSkus        = { value = var.allowed_vm_sku_sizes }
    requiredTags       = { value = var.required_tags }
    minimumTlsVersions = { value = ["TLS1_2", "TLS1_3"] }
  })
}

resource "azurerm_management_group_policy_assignment" "custom_guardrails" {
  count = (local.mg_scope && var.enable_custom_guardrails) ? 1 : 0

  name                 = "${var.name_prefix}-guardrails"
  display_name         = "Compliance baseline - preventive guardrails"
  description          = "Preventive half of the baseline. Denies at request time what the regulatory initiatives can only report after the fact."
  policy_definition_id = azurerm_policy_set_definition.custom_guardrails.id
  management_group_id  = var.management_group_id
  enforce              = var.enforcement_mode == "Default"
  location             = var.location
  parameters           = local.guardrail_parameters

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }

  non_compliance_message {
    content = "Blocked by the compliance baseline guardrails. If this is a legitimate exception, raise an exemption with a justification and an expiry date - see docs in CONTROLS.md, not a policy edit."
  }
}

resource "azurerm_subscription_policy_assignment" "custom_guardrails" {
  count = (!local.mg_scope && var.enable_custom_guardrails) ? 1 : 0

  name                 = "${var.name_prefix}-guardrails"
  display_name         = "Compliance baseline - preventive guardrails"
  description          = "Preventive half of the baseline, scoped to a single subscription."
  policy_definition_id = azurerm_policy_set_definition.custom_guardrails.id
  subscription_id      = "/subscriptions/${var.subscription_id}"
  enforce              = var.enforcement_mode == "Default"
  location             = var.location
  parameters           = local.guardrail_parameters

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }

  non_compliance_message {
    content = "Blocked by the compliance baseline guardrails. Raise an exemption with a justification and an expiry date rather than editing the policy."
  }
}
