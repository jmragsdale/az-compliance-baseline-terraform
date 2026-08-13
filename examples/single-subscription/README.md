# Example: single subscription, FedRAMP Moderate, near-zero cost

For when you do not own the tenant root group. `deployment_scope =
"single_subscription"` gates off every `Microsoft.Management` resource, so this
plans and applies with nothing more than Contributor + User Access Administrator
on one subscription.

## What you lose compared to `org-wide`

| Capability | Reason |
|---|---|
| Management group hierarchy | Requires tenant-root RBAC and `Microsoft.Management` registration |
| Inherited policy across future subscriptions | Subscription-scoped assignments apply to one subscription, full stop |
| MG-scoped exemptions | Exemptions are scoped to the subscription or below |
| A single remediation identity across the estate | The identity is confined to this subscription |

Everything else is identical. The same six custom policy definitions, the same
regulatory initiatives, the same DINE diagnostics initiative, the same WORM
archive and the same CMK posture — just assigned one level down.

## What this actually costs

| Item | Monthly |
|---|---|
| Log Analytics ingestion (Activity Log only, quiet subscription) | under USD 5 |
| Key Vault Premium — 3 HSM keys + operations | roughly USD 3–5 |
| Storage: archive account, cool tier, low volume | under USD 1 |
| Policy evaluation, Activity Log alerts, action group | free |
| Defender for Cloud | **USD 0** — every plan is off |

The `log_analytics_daily_quota_gb = 1` cap in this example is a deliberate
lab-only choice. It protects the budget by **dropping audit records** once hit,
which is an AU-4/AU-5 violation in a real authorization boundary. Remove it
before using this shape for anything that matters.

## Try it

```bash
terraform -chdir=examples/single-subscription init
terraform -chdir=examples/single-subscription plan
```

Note that `guardrail_effect = "Audit"` here. In a subscription you share with
other teams, a `Deny` you cannot defend in a meeting gets your policy assignment
deleted by someone with Owner. Report first, then earn the Deny.
