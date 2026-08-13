#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Evidence bundle export.
#
# Produces the artifacts an assessor actually asks for, as files with timestamps
# rather than portal screenshots:
#
#   policy-state-summary.json      per-initiative compliance roll-up (CA-2, CA-7)
#   policy-noncompliant.csv        every non-compliant resource, flat
#   policy-assignments.json        what is assigned, at what scope, in what mode
#   policy-exemptions.csv          every deviation, with justification and expiry (CA-5)
#   regulatory-compliance.json     Defender regulatory standard pass/fail per control
#   defender-assessments.csv       unhealthy Defender assessments (RA-5, SI-4)
#   defender-pricing.json          which plans are actually paid for
#   secure-score.json              CA-7 trend datapoint
#   activity-log-diagnostics.json  proof the Activity Log is being captured (AU-2)
#   role-assignments.csv           who holds what at the boundary scope (AC-2, AC-6)
#   storage-immutability.json      WORM policy state -- Locked vs Unlocked (AU-9(3))
#   manifest.json                  what ran, when, against what, and what failed
#
# Usage:
#   ./scripts/export-evidence.sh --subscription <guid> [--management-group <name>]
#                                [--out evidence/] [--standard <name>]
#
# Requires: az CLI (logged in), jq. Read-only: every call below is a GET.
# Security Reader at the boundary scope is sufficient.
#
# Nothing here writes to Azure. If a command fails -- usually because the signed-in
# principal lacks a read role, or because Defender is not enabled -- the failure is
# recorded in manifest.json rather than silently producing an empty file. An
# evidence bundle that quietly omits a section is worse than one that says
# "permission denied", because the gap is invisible in the PDF.
# ---------------------------------------------------------------------------
set -uo pipefail

SUBSCRIPTION=""
MANAGEMENT_GROUP=""
OUT_DIR="evidence"
STANDARD=""

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --subscription) SUBSCRIPTION="${2:-}"; shift 2 ;;
    --management-group) MANAGEMENT_GROUP="${2:-}"; shift 2 ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --standard) STANDARD="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

command -v az >/dev/null || { echo "az CLI is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

if [ -z "$SUBSCRIPTION" ]; then
  SUBSCRIPTION="$(az account show --query id -o tsv 2>/dev/null || true)"
fi
[ -n "$SUBSCRIPTION" ] || { echo "--subscription is required (or run 'az login' first)" >&2; exit 1; }

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE="${OUT_DIR}/${TIMESTAMP}"
mkdir -p "$BUNDLE"

SUB_SCOPE="/subscriptions/${SUBSCRIPTION}"
if [ -n "$MANAGEMENT_GROUP" ]; then
  SCOPE="/providers/Microsoft.Management/managementGroups/${MANAGEMENT_GROUP}"
else
  SCOPE="$SUB_SCOPE"
fi

FAILURES=()
step() { printf '\033[1m==> %s\033[0m\n' "$1"; }
record_failure() { FAILURES+=("$1"); printf '    \033[33mskipped: %s\033[0m\n' "$1"; }

# run <label> <output-file> <az args...>
run() {
  local label="$1" out="$2"; shift 2
  if "$@" >"$out" 2>"${out}.err"; then
    rm -f "${out}.err"
  else
    record_failure "${label}: $(head -c 300 "${out}.err" 2>/dev/null | tr '\n' ' ')"
    rm -f "$out" "${out}.err"
  fi
}

echo "evidence bundle: ${BUNDLE}"
echo "scope:           ${SCOPE}"
echo

# ---------------------------------------------------------------------------
# Azure Policy - CA-2, CA-7, CM-6
# ---------------------------------------------------------------------------
step "policy compliance summary"
run "policy state summarize" "${BUNDLE}/policy-state-summary.json" \
  az policy state summarize --scope "$SCOPE" -o json

step "non-compliant resources"
if az policy state list --scope "$SCOPE" --filter "ComplianceState eq 'NonCompliant'" \
     --query "[].{resource:resourceId, policy:policyDefinitionName, assignment:policyAssignmentName, effect:policyDefinitionAction, state:complianceState, evaluated:timestamp}" \
     -o json >"${BUNDLE}/policy-noncompliant.json" 2>"${BUNDLE}/.err"; then
  rm -f "${BUNDLE}/.err"
  jq -r '["resource_id","policy","assignment","effect","state","evaluated"],
         (.[] | [.resource, .policy, .assignment, .effect, .state, .evaluated])
         | @csv' "${BUNDLE}/policy-noncompliant.json" >"${BUNDLE}/policy-noncompliant.csv"
else
  record_failure "policy state list: $(head -c 300 "${BUNDLE}/.err" | tr '\n' ' ')"
  rm -f "${BUNDLE}/.err"
fi

step "policy assignments"
run "policy assignment list" "${BUNDLE}/policy-assignments.json" \
  az policy assignment list --scope "$SCOPE" --disable-scope-strict-match -o json

# CA-5: every exemption is a deviation an assessor will ask about. Exporting the
# justification and expiry alongside the compliance state is what turns "we have
# exceptions" into a defensible position.
step "policy exemptions"
if az policy exemption list --scope "$SCOPE" --disable-scope-strict-match -o json \
     >"${BUNDLE}/policy-exemptions.json" 2>"${BUNDLE}/.err"; then
  rm -f "${BUNDLE}/.err"
  jq -r '["name","category","expires_on","assignment","description"],
         (.[] | [.name, .exemptionCategory, (.expiresOn // "NO EXPIRY - FINDING"), .policyAssignmentId, .description])
         | @csv' "${BUNDLE}/policy-exemptions.json" >"${BUNDLE}/policy-exemptions.csv"
else
  record_failure "policy exemption list: $(head -c 300 "${BUNDLE}/.err" | tr '\n' ' ')"
  rm -f "${BUNDLE}/.err"
fi

# ---------------------------------------------------------------------------
# Defender for Cloud - RA-5, SI-4, CA-7
# Regulatory compliance endpoints are subscription-scoped only.
# ---------------------------------------------------------------------------
step "Defender regulatory compliance standards"
run "regulatory compliance standards" "${BUNDLE}/regulatory-standards.json" \
  az rest --method get --url \
  "https://management.azure.com${SUB_SCOPE}/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview"

if [ -n "$STANDARD" ]; then
  step "Defender regulatory compliance controls for '${STANDARD}'"
  run "regulatory compliance controls" "${BUNDLE}/regulatory-compliance.json" \
    az rest --method get --url \
    "https://management.azure.com${SUB_SCOPE}/providers/Microsoft.Security/regulatoryComplianceStandards/${STANDARD}/regulatoryComplianceControls?api-version=2019-01-01-preview"
else
  echo "    (pass --standard 'FedRAMP_H' or similar for per-control detail)"
fi

step "Defender assessments"
if az security assessment list --query "[].{name:displayName, status:status.code, cause:status.cause, resource:resourceDetails.id}" \
     -o json >"${BUNDLE}/defender-assessments.json" 2>"${BUNDLE}/.err"; then
  rm -f "${BUNDLE}/.err"
  jq -r '["assessment","status","cause","resource_id"],
         (.[] | select(.status != "Healthy") | [.name, .status, .cause, .resource])
         | @csv' "${BUNDLE}/defender-assessments.json" >"${BUNDLE}/defender-assessments.csv"
else
  record_failure "security assessment list: $(head -c 300 "${BUNDLE}/.err" | tr '\n' ' ')"
  rm -f "${BUNDLE}/.err"
fi

# Which plans are actually paid for. "We have Defender enabled" is a claim; this
# is the evidence, and it also explains the invoice.
step "Defender plan tiers"
run "security pricing list" "${BUNDLE}/defender-pricing.json" \
  az security pricing list -o json

step "secure score"
run "secure score" "${BUNDLE}/secure-score.json" \
  az security secure-scores list -o json

step "security contacts"
run "security contact list" "${BUNDLE}/security-contacts.json" \
  az security contact list -o json

# ---------------------------------------------------------------------------
# Audit pipeline - AU-2, AU-9, AU-11
# ---------------------------------------------------------------------------
step "Activity Log diagnostic settings"
run "activity log diagnostics" "${BUNDLE}/activity-log-diagnostics.json" \
  az monitor diagnostic-settings subscription list -o json

step "Log Analytics workspaces and retention"
run "log analytics workspaces" "${BUNDLE}/log-analytics-workspaces.json" \
  az monitor log-analytics workspace list \
  --query "[].{name:name, rg:resourceGroup, retentionDays:retentionInDays, dailyQuotaGb:workspaceCapping.dailyQuotaGb, sku:sku.name}" -o json

# AU-9(3): the question an assessor asks is not "is there an immutability policy"
# but "is it Locked". Unlocked is a finding, and this file is where that shows.
step "storage immutability policy state"
run "storage account immutability" "${BUNDLE}/storage-immutability.json" \
  az storage account list \
  --query "[].{name:name, rg:resourceGroup, immutability:immutableStorageWithVersioning, publicAccess:allowBlobPublicAccess, sharedKey:allowSharedKeyAccess, minTls:minimumTlsVersion, replication:sku.name}" -o json

# ---------------------------------------------------------------------------
# Identity - AC-2, AC-6
# ---------------------------------------------------------------------------
step "role assignments at the boundary scope"
if az role assignment list --scope "$SCOPE" --include-inherited \
     --query "[].{principal:principalId, type:principalType, role:roleDefinitionName, scope:scope}" \
     -o json >"${BUNDLE}/role-assignments.json" 2>"${BUNDLE}/.err"; then
  rm -f "${BUNDLE}/.err"
  jq -r '["principal_id","principal_type","role","scope"],
         (.[] | [.principal, .type, .role, .scope]) | @csv' \
    "${BUNDLE}/role-assignments.json" >"${BUNDLE}/role-assignments.csv"
else
  record_failure "role assignment list: $(head -c 300 "${BUNDLE}/.err" | tr '\n' ' ')"
  rm -f "${BUNDLE}/.err"
fi

# ---------------------------------------------------------------------------
# Manifest. This is the part that makes the bundle honest.
# ---------------------------------------------------------------------------
step "manifest"
COMPLIANT_PCT="$(jq -r '.value[0].results.resourceDetails[]? | select(.complianceState=="Compliant") | .count' \
  "${BUNDLE}/policy-state-summary.json" 2>/dev/null | head -1)"

jq -n \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg subscription "$SUBSCRIPTION" \
  --arg scope "$SCOPE" \
  --arg standard "${STANDARD:-not-requested}" \
  --arg tool "az-compliance-baseline-terraform/scripts/export-evidence.sh" \
  --arg az_version "$(az version --query '\"azure-cli\"' -o tsv 2>/dev/null || echo unknown)" \
  --arg compliant "${COMPLIANT_PCT:-unknown}" \
  --argjson failures "$(printf '%s\n' "${FAILURES[@]:-}" | jq -R . | jq -s 'map(select(length>0))')" \
  --argjson files "$(cd "$BUNDLE" && ls -1 | jq -R . | jq -s .)" \
  '{
     generated_utc: $generated,
     subscription_id: $subscription,
     scope: $scope,
     regulatory_standard: $standard,
     generated_by: $tool,
     az_cli_version: $az_version,
     compliant_resource_count: $compliant,
     files: $files,
     incomplete_sections: $failures,
     caveats: [
       "Policy compliance state reflects the last evaluation cycle, not the current instant. Azure Policy evaluates every 24 hours and on resource change; a scan triggered immediately after an apply will under-report.",
       "Defender assessments require the relevant Defender plan to be enabled. Absent findings for a resource type usually means the plan is off, not that the resource type is clean.",
       "This bundle is a point-in-time snapshot of technical control state. It is not an assessment, and it says nothing about the administrative and procedural control families FedRAMP also requires.",
       "Sections listed in incomplete_sections produced no data. Check them before submitting -- a missing section is usually a missing read role, not a clean result."
     ]
   }' >"${BUNDLE}/manifest.json"

echo
if [ "${#FAILURES[@]}" -gt 0 ]; then
  printf '\033[33m%d section(s) incomplete - see manifest.json incomplete_sections\033[0m\n' "${#FAILURES[@]}"
fi
printf '\033[32mevidence bundle written to %s\033[0m\n' "$BUNDLE"
echo "Note: evidence/ is gitignored. It contains subscription and principal identifiers."
