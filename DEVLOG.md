# Development Log - az-compliance-baseline-terraform

Working notes: decisions, dead ends, and the reasoning behind the shape of this repo.

## 2026-08-13 - Initial build

**Why a `controls.yaml` instead of prose in the README.**
Compliance repos usually claim framework coverage in a README table that nothing
verifies. The table drifts from the code within a release or two and there is no
signal when it does. Here the matrix is generated from `controls/controls.yaml`,
each control names the Terraform address implementing it, and CI fails the build
if that address stops existing. The claim and the code cannot separate silently.

**Why plan-only verification.**
Org-scoped resources cannot be applied without owning an organization. Rather
than pretend otherwise, CI runs `terraform init -backend=false` + `validate` and
static analysis only. The README states plainly which controls are plan-verified
versus apply-verified. Overclaiming here is the fastest way to lose credibility
with anyone who has actually sat through an assessment.

**Why FedRAMP baseline is a variable, not a fork.**
Moderate and High differ mostly in parameter values (retention windows, MFA
scope, encryption strength, availability requirements) rather than in which
controls exist. `var.fedramp_baseline` drives those parameters so the two
baselines share one code path and stay in sync.

**Scope honesty.**
This repo implements *technical* controls. FedRAMP and NIST 800-53 include large
administrative and procedural families - awareness and training, personnel
security, physical protection, most of planning and program management - that no
amount of Terraform will satisfy. The generated coverage percentages count
technical controls only and `CONTROLS.md` says so at the top.

## 2026-08-13 - Azure-specific notes

**The GUID problem, and why one framework ships unassigned.**
Azure's built-in regulatory initiatives are referenced by bare GUIDs. They are
stable, but they are not reliably discoverable from documentation and they differ
between commercial and sovereign clouds. I was confident enough in FedRAMP
Moderate, FedRAMP High, NIST 800-53 Rev 5 and the Microsoft Cloud Security
Benchmark to ship them as verified. I was not confident in CIS Azure Foundations
v3.0.0, so it ships with `id = null, verified = false` and is simply not
assigned. Every plan prints `initiatives_requiring_guid_verification` telling you
what is missing and the `az` command that resolves it. Assigning a guessed GUID
would have produced a compliance dashboard that is green against the wrong
benchmark version - which is worse than a visible gap, because nobody
investigates green.

**Only one FedRAMP initiative is ever assigned.**
Assigning Moderate and High simultaneously looks thorough and is actively
harmful: overlapping deployIfNotExists policies race each other on the same
resources, and the dashboard double-counts every finding. `fedramp_baseline`
selects exactly one via `local.baseline.primary_initiative_key`.

**Why the encryption module does not own the Key Vault diagnostic setting.**
First cut had `encryption` taking a workspace ID from `logging`, and `logging`
taking a CMK from `encryption`. Terraform's graph is per-resource so it may well
have resolved, but a module pair with edges in both directions is a trap for the
next person who adds an innocent-looking output. Moved the Key Vault diagnostic
setting into `logging` and made the dependency strictly one-way:
`encryption -> logging -> {defender, network}`. The comment in
`modules/logging/main.tf` says why, so nobody "fixes" it back.

**The NSG rule that turned out to be load-bearing.**
An explicit `deny-all-inbound` at priority 4096 out-ranks Azure's implicit
`AllowVnetInBound` at 65000. Written on its own, that rule black-holes all
intra-VNet traffic - including private endpoint access to Key Vault, which is how
the whole boundary talks to its own root of trust. The fix is an explicit
`allow-vnet-inbound` at 3900 restating the implicit rule above the deny. Worth
recording because the naive "just add a deny-all" advice you find everywhere
produces an outage on a real VNet.

**A bare `if =` key silently disabled Checkov.**
Azure Policy rules are JSON with a top-level `if`. Written as
`jsonencode({ if = {...} })` Terraform is perfectly happy, `tofu fmt` is happy,
and python-hcl2 - which Checkov and several other scanners use - fails to parse
the file. Not as a finding: as a "parsing error" line in the summary that is easy
to scroll past, while the entire file goes unscanned. Quoting the key
(`"if" = {...}`) fixes it. Two files were affected and both are now commented so
the quoting does not get tidied away. This is the concrete argument for running
more than one scanner: a single engine failing open looks identical to a clean
result.

**What the flow log sink cost in strictness, and why I left it.**
Network Watcher authenticates to its storage sink with a shared key and delivers
from the platform network, not from inside the VNet. So the flow log account
cannot have `shared_access_key_enabled = false` or private-endpoint-only access,
which are exactly the two things the audit archive does have. Rather than quietly
loosen both accounts to match, the flow log account is configured differently,
the constraint is written in the file header, the Checkov skips name the service
limitation, and the Conftest policy encodes the exception by *tag* rather than by
resource name so it cannot be widened by renaming something.

**Locking WORM is a manual step and that is the whole point.**
`az storage account immutability-policy update --state Locked` is irreversible
for the life of the account. A module that runs it on your first apply has
removed your ability to recover from a mistyped retention period. It is surfaced
in `post_apply_manual_steps`, tagged on the resource, flagged by a custom
Defender assessment, and called out in the README - which is about as loud as an
unlocked policy can be made without doing the irreversible thing for you.

## 2026-08-13 - First real `terraform validate`

Authored in a sandbox with the provider registry blocked, so this was the first
time the config met the actual azurerm schema. Four hard errors, all in the
category of "plausible argument name that does not exist":

- **`azurerm_storage_management_policy`** - the `version` and `snapshot` blocks
  spell it `change_tier_to_cool_after_days_since_creation`; only `base_blob`
  uses the `tier_to_*` prefix. Same concept, different names, no way to catch it
  without the schema.
- **NSG rule descriptions cap at 140 characters.** Two rules carried the full
  framework rationale inline and blew the limit. The reasoning moved into
  comments, where it belongs anyway - a comment has no length limit and the
  description field is not where an auditor reads justifications.
- **`enable_rbac_authorization`** is renamed `rbac_authorization_enabled`, and
  the `metric` block inside diagnostic settings is superseded by
  `enabled_metric`. Both still work under `~> 4.0` but are removed in v5.

`azurerm_security_center_auto_provisioning` stays, deprecated, with a comment:
it is still the only Terraform surface for the setting, and Microsoft is moving
the capability to agentless scanning. Documented rather than silently deferred.

The three deprecation warnings were fixed rather than tolerated, because a repo
whose whole premise is "the code backs the compliance claim" cannot ship with a
validate step that prints warnings nobody reads.
