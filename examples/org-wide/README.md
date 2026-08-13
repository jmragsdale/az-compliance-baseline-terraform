# Example: org-wide, FedRAMP High

The full posture. Builds the management group hierarchy, assigns the FedRAMP
High initiative alongside NIST 800-53 Rev 5 and the Microsoft Cloud Security
Benchmark at MG scope, and turns on every Defender plan.

## What this needs before it will apply

| Prerequisite | Why |
|---|---|
| `Microsoft.Management` registered in the tenant | Management group resources fail with a provider-not-registered error otherwise |
| Owner, or Contributor + User Access Administrator, at the parent MG (or tenant root) | The module creates MGs *and* role assignments for the remediation identity |
| A verified GUID for CIS Azure Foundations v3.0.0 | This repo ships that entry unverified; without an override the CIS initiative is skipped and the output says so |
| An existing egress path (Azure Firewall, NVA, or private endpoints for everything) | `deny_internet_egress = true` will otherwise break agent enrolment and Key Vault access |

## What changes because `fedramp_baseline = "high"`

| Parameter | Moderate | High (this example) |
|---|---|---|
| Regulatory initiative assigned | FedRAMP Moderate | FedRAMP High |
| Log Analytics interactive retention | 365 days | 730 days |
| Archive WORM window | 1095 days | 2555 days |
| Archive replication | GRS | RAGRS (readable secondary) |
| CMK size / rotation | RSA-HSM 3072, P365D | RSA-HSM 4096, P180D |
| Disk encryption | Customer key | Platform **and** customer key |
| Defender for Servers | P1 (agentless) | P2 (VA + file integrity monitoring) |
| Defender for Storage malware scanning | off | on |

## Rollout order that does not break the tenant

1. `guardrail_effect = "Audit"`, `policy_assignment_enforcement = "DoNotEnforce"`. Apply. Wait 24h for the first full evaluation cycle.
2. Read the compliance dashboard. Everything red here is something that would have been *blocked*.
3. File exemptions for the legitimate cases, with expiry dates.
4. Flip `guardrail_effect = "Deny"`.
5. Flip `deny_internet_egress = true` only after the firewall path is verified.
6. Lock the archive immutability policy last, once the retention window is confirmed. It is irreversible.

## Cost warning

Every Defender plan plus the DDoS Network Protection plan are enabled here. DDoS
alone is roughly USD 2,900/month per tenant. See the Cost section of the root
README before copying this file verbatim.
