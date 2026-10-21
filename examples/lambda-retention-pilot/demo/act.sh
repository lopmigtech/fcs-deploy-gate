#!/usr/bin/env bash
# Puts the pilot repository into the state of one act and commits it, so the demo never
# edits a file by hand. Each act is a complete state, not a change on top of the previous
# one, so the acts can be run in any order and repeated:
#
#   1  advisory,  no Exclusions, log group without retention   today's world: it ships
#   2  enforcing, no Exclusions, no retention                  the Gate blocks, apply never runs
#   3  enforcing, the KMS Finding excluded, no retention       one Finding left, still blocked
#   4  enforcing, excluded, retention_in_days = 30             clear Verdict, apply runs
#
# Usage: demo/act.sh <1|2|3|4>        (demo/act1.sh .. demo/act4.sh are shorthands)
# Environment:
#   DEMO_APPROVER                  the name in approved_by of the Exclusion (default: git user.name)
#   DEMO_EXCLUDE_ACCESS_ANALYZER=1 add the second entry when "IAM Access Analyzer Not Enabled" shows
#   DEMO_PUSH=1                    push after committing (each push shows as a pipeline in GitLab)
set -euo pipefail
cd "$(dirname "$0")/.."

act=${1:-}
case "$act" in
  1|2|3|4) ;;
  *) echo "usage: $0 <1|2|3|4>" >&2; exit 2 ;;
esac

PIPELINE=.gitlab-ci.yml
TF=lambda/main.tf
EXCLUSIONS=.fcs-gate.yml
RESOURCE='resource "aws_cloudwatch_log_group" "pilot" {'

set_mode() {
  sed -E -i "s/^(  FCS_GATE_MODE: )[a-z]+/\1$1/" "$PIPELINE"
  grep -qE "^  FCS_GATE_MODE: $1" "$PIPELINE" || { echo "could not set FCS_GATE_MODE in $PIPELINE" >&2; exit 1; }
}

retention_off() {
  sed -i '/^  retention_in_days *=/d' "$TF"
}

retention_on() {
  retention_off
  sed -i "s/^$RESOURCE\$/&\n  retention_in_days = 30/" "$TF"
  grep -q '^  retention_in_days = 30' "$TF" || { echo "could not add retention_in_days to $TF" >&2; exit 1; }
}

exclusions_off() {
  rm -f "$EXCLUSIONS"
}

exclusions_on() {
  local approver
  approver=${DEMO_APPROVER:-$(git config user.name || true)}
  if [ -z "$approver" ]; then
    echo "set DEMO_APPROVER to the Security team member who approved the Exclusion" >&2
    exit 1
  fi
  {
    echo "exclusions:"
    echo "  - rule: iac/d6b2ef53-b734-49cf-b736-f71a2dc70e4f"
    echo "    file: main.tf"
    echo "    reason: Log group encryption with a customer-managed key is outside the retention pilot."
    echo "    expires: 2026-11-30"
    echo "    approved_by: \"$approver\""
    if [ "${DEMO_EXCLUDE_ACCESS_ANALYZER:-0}" = "1" ]; then
      echo "  - rule: iac/d5900282-4330-48df-b93f-1d76f44f33a2"
      echo "    file: main.tf"
      echo "    reason: IAM Access Analyzer is enabled per account, not in this module."
      echo "    expires: 2026-11-30"
      echo "    approved_by: \"$approver\""
    fi
  } > "$EXCLUSIONS"
}

case "$act" in
  1) set_mode advisory;  exclusions_off; retention_off; message="Act one: advisory, the gap ships" ;;
  2) set_mode enforcing; exclusions_off; retention_off; message="Act two: the Gate enforces" ;;
  3) set_mode enforcing; exclusions_on;  retention_off; message="Act three: exclude the KMS Finding, approved and expiring" ;;
  4) set_mode enforcing; exclusions_on;  retention_on;  message="Act four: thirty days of retention" ;;
esac

git add -A
if git diff --cached --quiet; then
  echo "act $act: the repository was already in this state; nothing to commit"
else
  git commit -q -m "$message"
  echo "act $act: committed \"$message\""
fi
if [ "${DEMO_PUSH:-0}" = "1" ]; then
  git push -q && echo "pushed"
fi

mode=$(sed -nE 's/^  FCS_GATE_MODE: ([a-z]+).*/\1/p' "$PIPELINE")
if [ -f "$EXCLUSIONS" ]; then exclusions=yes; else exclusions=no; fi
if grep -q '^  retention_in_days' "$TF"; then retention=30; else retention=none; fi
echo "state: mode=$mode  exclusions=$exclusions  retention=$retention"
