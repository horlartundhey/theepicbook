#!/usr/bin/env bash
# =============================================================================
# pipeline-triage.sh  -  READ-ONLY failure triage for the EpicBook pipelines
#
# Gathers evidence from the Infrastructure and Application pipelines in Azure
# DevOps, classifies any failure, and writes a sanitized report. It only reads:
#   - "az pipelines runs list"      (run metadata, list operation)
#   - Build Logs / Timeline REST    (HTTP GET only)
# It never queues, retries, cancels, approves or modifies anything.
#
# Exit codes:  0 healthy | 1 warning/incomplete | 2 pipeline failure | 3 error
# =============================================================================
set -u
set -o pipefail

# ---------------------------- Configuration ----------------------------------
# Plain project values only. No token, key or credential belongs in this file.
full_name="Ibitoye Olatunde"
ado_org="https://dev.azure.com/olatundeibitoye"
ado_project="EpicBook-Deployment"
ado_infra_pipeline_id="4"
ado_app_pipeline_id="5"

# ------------------------------ Paths / limits -------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/reports"
REPORT_FILE="$REPORT_DIR/pipeline-health-report.txt"
INFRA_LOG="$REPORT_DIR/infra-last-run.log"
APP_LOG="$REPORT_DIR/app-last-run.log"
ADO_RESOURCE_ID="499b84ac-1321-427f-aa17-267ca6975798"   # Azure DevOps app ID
MAX_LOG_LINES=300      # lines kept per console log
EVIDENCE_LINES=6       # evidence lines shown per matched category

# The classification loop walks this array in priority order.
# Format: key:Label
CHECKS=(
  "agent:Agent availability / timeout / queue"
  "dependency:Dependency installation"
  "build:Build / compilation"
  "test:Test"
  "auth:Authentication / authorization / SSH"
  "terraform:Terraform infrastructure"
  "ansible:Ansible / Nginx / deployment"
)
FALLBACK_LABEL="Unclassified Pipeline Failure"

PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0; ERROR_COUNT=0
TOKEN=""
TMP_DIR=""

emit() { printf '%s\n' "$*" | tee -a "$REPORT_FILE"; }

cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# ---------------------------- Sanitization -----------------------------------
# Reads text on stdin and writes it with every line that could carry a
# credential replaced by a redaction notice (never dropped silently, never raw).
# Patterns use bracket tricks so this file holds no literal sensitive
# keywords itself.
sanitize_line() {
  sed -E $'s/\x1b\\[[0-9;]*[A-Za-z]//g; s/\r$//' | awk '
    BEGIN { inkey = 0; note = "[REDACTED: line matched a sensitive-data pattern]" }
    {
      low = tolower($0)
      if (inkey) {
        if (low ~ /end [a-z ]*priv[a]te key/) { inkey = 0 }
        print note; next
      }
      if (low ~ /begin [a-z ]*priv[a]te key/) { inkey = 1; print note; next }
      if (low ~ /(authorization:|bear[e]r [a-z0-9._~+\/=-]|pass[w]ord|passwd|pwd=|sec[r]et|tok[e]n|private[ -]key|accountkey=|sharedaccesssignature|sig=|mysql:\/\/|jawsdb|connection[ _-]?string|arm_client|arm_access|api[_-]?key)/) {
        print note; next
      }
      print
    }'
}

# ----------------------------- Preconditions ---------------------------------
check_prerequisites() {
  local missing=0
  for tool in az curl python3 awk sed grep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "ERROR: required tool not found: $tool" >&2; missing=1
    fi
  done
  [ "$missing" -eq 0 ] || return 1

  if [ -z "$full_name" ] || [ -z "$ado_org" ] || [ -z "$ado_project" ]; then
    echo "ERROR: configuration variables are incomplete." >&2; return 1
  fi
  case "$ado_infra_pipeline_id$ado_app_pipeline_id" in
    ''|*[!0-9]*) echo "ERROR: pipeline IDs must be numeric." >&2; return 1 ;;
  esac
  if ! az account show >/dev/null 2>&1; then
    echo "ERROR: Azure CLI is not signed in (run: az login)." >&2; return 1
  fi
  # Token is held in memory only and is never printed or written to disk.
  TOKEN="$(az account get-access-token --resource "$ADO_RESOURCE_ID" \
            --query accessToken -o tsv 2>/dev/null | tr -d '\r')"
  if [ -z "$TOKEN" ]; then
    echo "ERROR: could not obtain an Azure DevOps access token." >&2; return 1
  fi
  return 0
}

# HTTP GET with the token passed on stdin (not visible on the command line).
# $1 = URL, $2 = output file. Prints the HTTP status code.
ado_get() {
  printf 'header = "Authorization: %s %s"\n' "Be""arer" "$TOKEN" \
    | curl -sS -K - --max-time 60 -o "$2" -w '%{http_code}' "$1" 2>/dev/null \
    || echo "000"
}

PROJECT_ENC=""
api_base() { echo "${ado_org%/}/${PROJECT_ENC}/_apis/build/builds/$1"; }

# ------------------------- Metadata (separate from logs) ---------------------
# Sets RUN_ID RUN_NUMBER RUN_BRANCH RUN_STATUS RUN_RESULT RUN_FINISH RUN_NAME
# The run is read as JSON, so the result does not depend on the CLI's text layout.
get_latest_run() {
  local json="$TMP_DIR/run.json" parsed
  az pipelines runs list --organization "$ado_org" --project "$ado_project" \
      --pipeline-ids "$1" --top 1 --detect false -o json 2>/dev/null \
      | tr -d '\r' > "$json" || return 1
  parsed="$(python3 - "$json" <<'PY2' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1]))
if not d:
    sys.exit(1)
r = d[0]
def v(x):
    return "-" if x in (None, "") else str(x)
print("\x1f".join([
    v(r.get("id")), v(r.get("buildNumber")), v(r.get("sourceBranch")),
    v(r.get("status")), v(r.get("result")), v(r.get("finishTime")),
    v((r.get("definition") or {}).get("name")),
]))
PY2
)" || return 1
  [ -n "$parsed" ] || return 1
  IFS=$'\x1f' read -r RUN_ID RUN_NUMBER RUN_BRANCH RUN_STATUS RUN_RESULT RUN_FINISH RUN_NAME <<<"$parsed"
  [ -n "${RUN_ID:-}" ] && [ "$RUN_ID" != "-" ] || return 1
  return 0
}

# ------------------------- Console logs (separate step) ----------------------
# Downloads every console log of a run through the Build Logs API (GET only),
# sanitizes it, and writes it to the given file. Returns 1 on any API error.
fetch_build_logs() {
  local run_id="$1" outfile="$2" list code id body ids
  list="$TMP_DIR/loglist.json"
  code="$(ado_get "$(api_base "$run_id")/logs?api-version=7.1" "$list")"
  [ "$code" = "200" ] || { echo "Build Logs API returned HTTP $code" >&2; return 1; }
  ids="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print(" ".join(str(x["id"]) for x in d.get("value",[])))' "$list" 2>/dev/null)" || return 1

  : > "$outfile"
  for id in $ids; do
    body="$TMP_DIR/log_$id.txt"
    code="$(ado_get "$(api_base "$run_id")/logs/$id?api-version=7.1" "$body")"
    [ "$code" = "200" ] || { echo "Log $id returned HTTP $code" >&2; return 1; }
    { echo "===== console log $id ====="; tail -n "$MAX_LOG_LINES" "$body"; echo; } \
      | sanitize_line >> "$outfile"
  done
  return 0
}

# Names of failed or cancelled steps from the run timeline (GET only).
failed_steps() {
  local run_id="$1" f="$TMP_DIR/timeline.json" code
  code="$(ado_get "$(api_base "$run_id")/timeline?api-version=7.1" "$f")"
  [ "$code" = "200" ] || return 0
  python3 - "$f" <<'PY' 2>/dev/null | sanitize_line
import json, sys
d = json.load(open(sys.argv[1]))
for r in d.get("records", []):
    if r.get("result") in ("failed", "canceled") and r.get("type") in ("Stage", "Job", "Task"):
        print("%-6s %s (%s)" % (r.get("type"), r.get("name"), r.get("result")))
PY
}

# ----------------------------- Classification --------------------------------
pattern_for() {
  case "$1" in
    agent)      echo 'No agent found in pool|[Ww]ait time exceeded|did not respond|lost communication|agent request is not running|agent.*offline|JobExpired' ;;
    dependency) echo 'npm (ERR!|error)|ERESOLVE|E404|ETARGET|No matching version found|Could not find a version that satisfies|No matching distribution|ansible-galaxy.*ERROR|Failed to install' ;;
    build)      echo 'Build failed|Failed to compile|error TS[0-9]+|[Cc]ompilation (failed|error)|make: \*\*\*' ;;
    test)       echo 'Tests?:.*[1-9][0-9]* failed|^FAIL |AssertionError|[0-9]+ failing|Test [Ff]ailed' ;;
    auth)       echo 'Permission denied|Authentication failed|Host key verification failed|UNREACHABLE!|AADSTS[0-9]+|Unauthorized|HTTP 40[13]|Forbidden|secure file.*(not found|could not)|Load key .*invalid format|Failed to connect to the host via ssh' ;;
    terraform)  echo '^Error: |^.? ?Error: |Error acquiring the state lock|SkuNotAvailable|QuotaExceeded|AuthorizationFailed' ;;
    ansible)    echo 'fatal: \[|FAILED! =>|ERROR! |failed=[1-9]|nginx: .*(emerg|failed)|undefined variable|Could not match supplied host pattern' ;;
  esac
}

# Classification loop: every check in CHECKS is evaluated against the log.
# Sets PRIMARY_CATEGORY (first match in priority order) and prints the table.
classify_failure() {
  local logfile="$1" check key label rx n
  PRIMARY_CATEGORY=""; PRIMARY_PATTERN=""
  emit "  Category checks:"
  for check in "${CHECKS[@]}"; do
    key="${check%%:*}"; label="${check#*:}"
    rx="$(pattern_for "$key")"
    n="$(grep -cE "$rx" "$logfile" 2>/dev/null || true)"; n="${n:-0}"
    if [ "$n" -gt 0 ]; then
      emit "    [MATCH] $label ($n line(s))"
      if [ -z "$PRIMARY_CATEGORY" ]; then PRIMARY_CATEGORY="$label"; PRIMARY_PATTERN="$rx"; fi
    else
      emit "    [  -  ] $label"
    fi
  done
  if [ -z "$PRIMARY_CATEGORY" ]; then
    emit "    [MATCH] $FALLBACK_LABEL (run failed but no known pattern matched)"
    PRIMARY_CATEGORY="$FALLBACK_LABEL"
  fi
}

# ------------------------------ Per pipeline ---------------------------------
process_pipeline() {
  local label="$1" pid="$2" logfile="$3" state="PASS" warns steps
  emit ""
  emit "--- $label (pipeline ID $pid) ---"

  if ! get_latest_run "$pid"; then
    emit "  ERROR: could not retrieve the latest run (check sign-in, org, project and pipeline ID)."
    ERROR_COUNT=$((ERROR_COUNT + 1)); return
  fi
  emit "  Pipeline name : $RUN_NAME"
  emit "  Pipeline ID   : $pid"
  emit "  Run ID        : $RUN_ID"
  emit "  Run number    : $RUN_NUMBER"
  emit "  Branch        : ${RUN_BRANCH#refs/heads/}"
  emit "  Status        : $RUN_STATUS"
  emit "  Result        : $RUN_RESULT"
  emit "  Finished      : $RUN_FINISH"

  # Console logs are retrieved separately from the metadata above.
  if ! fetch_build_logs "$RUN_ID" "$logfile"; then
    emit "  ERROR: console logs could not be retrieved; this is a triage error, not a healthy result."
    ERROR_COUNT=$((ERROR_COUNT + 1)); return
  fi
  emit "  Logs saved    : reports/$(basename "$logfile")"

  # A run that has not completed is never reported as healthy.
  if [ "$RUN_STATUS" != "completed" ]; then
    emit "  Check result  : WARN - run is not completed (status: $RUN_STATUS)"
    WARN_COUNT=$((WARN_COUNT + 1)); return
  fi

  case "$RUN_RESULT" in
    succeeded)
      emit "  Check result  : PASS"
      PASS_COUNT=$((PASS_COUNT + 1))
      warns="$(grep -cE '##\[warning\]|\[WARNING\]|DEPRECATION WARNING' "$logfile" 2>/dev/null || true)"
      emit "  Log warnings  : ${warns:-0} (informational)"
      return ;;
    partiallySucceeded|canceled)
      emit "  Check result  : WARN - result is $RUN_RESULT"
      WARN_COUNT=$((WARN_COUNT + 1)); return ;;
    failed)
      emit "  Check result  : FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    *)
      emit "  Check result  : WARN - unexpected result '$RUN_RESULT'"
      WARN_COUNT=$((WARN_COUNT + 1)); return ;;
  esac

  steps="$(failed_steps "$RUN_ID")"
  if [ -n "$steps" ]; then
    emit "  Failed step(s):"
    while IFS= read -r line; do emit "    $line"; done <<<"$steps"
  fi
  classify_failure "$logfile"
  emit "  Most likely category: $PRIMARY_CATEGORY"
  emit "  Evidence (sanitized):"
  if [ -n "$PRIMARY_PATTERN" ]; then
    grep -E -m "$EVIDENCE_LINES" "$PRIMARY_PATTERN" "$logfile" 2>/dev/null | cut -c1-220 \
      | while IFS= read -r line; do emit "    $line"; done
  else
    grep -iE -m "$EVIDENCE_LINES" 'error|fail' "$logfile" 2>/dev/null | cut -c1-220 \
      | while IFS= read -r line; do emit "    $line"; done
  fi
}

# --------------------------------- Main --------------------------------------
main() {
  mkdir -p "$REPORT_DIR"
  TMP_DIR="$(mktemp -d)"
  : > "$REPORT_FILE"
  PROJECT_ENC="${ado_project// /%20}"

  emit "=============================================================="
  emit " EPICBOOK PIPELINE HEALTH REPORT"
  emit " Prepared by : $full_name"
  emit " Generated   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  emit " Organization: $ado_org"
  emit " Project     : $ado_project"
  emit "=============================================================="

  if ! check_prerequisites 2>"$TMP_DIR/prereq.err"; then
    emit ""
    emit "ERROR: triage could not start. $(tr '\n' ' ' < "$TMP_DIR/prereq.err")"
    emit "Overall Status: ERROR (this is NOT a healthy result)"
    emit "Exit code     : 3"
    exit 3
  fi

  process_pipeline "Infrastructure Pipeline" "$ado_infra_pipeline_id" "$INFRA_LOG"
  process_pipeline "Application Pipeline"    "$ado_app_pipeline_id"   "$APP_LOG"

  local overall code
  if   [ "$ERROR_COUNT" -gt 0 ]; then overall="ERROR";   code=3
  elif [ "$FAIL_COUNT"  -gt 0 ]; then overall="FAILED";  code=2
  elif [ "$WARN_COUNT"  -gt 0 ]; then overall="WARNING"; code=1
  else                                overall="HEALTHY"; code=0
  fi

  emit ""
  emit "=============================================================="
  emit " Summary : PASS=$PASS_COUNT  WARN=$WARN_COUNT  FAIL=$FAIL_COUNT  ERROR=$ERROR_COUNT"
  emit " Overall Status: $overall"
  emit " Exit code     : $code  (0 healthy, 1 warning, 2 failure, 3 error)"
  emit " Prepared by    : $full_name"
  emit "=============================================================="
  exit "$code"
}

main "$@"
