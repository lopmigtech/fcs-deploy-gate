#!/usr/bin/env bash
# Runs the pilot's own pipeline file on this machine with gitlab-ci-local (WALKTHROUGH.md,
# 5E): plan and the gate job only, or the whole pipeline with --deploy, in which case
# apply runs when the Gate's job passes and the resources go into the sandbox account.
#
# Usage: demo/run.sh [--deploy] [more gitlab-ci-local options, for example --fetch-includes]
# Environment, exported once in the shell (DEMO.md, "Before the demo"):
#   PILOT_PROJECT_ID   the number labelled "Project ID" on the pilot project's page
#   GITLAB_USER        your GitLab username, for the Terraform state
#   GL_TOKEN           a personal access token with the api scope, in the job token's place
#   FALCON_CLIENT_ID, FALCON_CLIENT_SECRET   the CI client
#   AWS_PROFILE        the sandbox profile, signed in with aws sso login
set -euo pipefail
cd "$(dirname "$0")/.."

missing=()
for name in PILOT_PROJECT_ID GITLAB_USER GL_TOKEN FALCON_CLIENT_ID FALCON_CLIENT_SECRET; do
  if [ -z "${!name:-}" ]; then missing+=("$name"); fi
done
if [ ${#missing[@]} -gt 0 ]; then
  echo "run.sh: export ${missing[*]} first (DEMO.md, Before the demo)" >&2
  exit 2
fi
case "$PILOT_PROJECT_ID" in
  ''|*[!0-9]*)
    echo "run.sh: PILOT_PROJECT_ID must be a number, the project id on the pilot project's page" >&2
    exit 2 ;;
esac
if [ -z "${AWS_PROFILE:-}${AWS_ACCESS_KEY_ID:-}" ]; then
  echo "run.sh: warning: neither AWS_PROFILE nor AWS_ACCESS_KEY_ID is set; Terraform will use the default profile" >&2
fi
if [ -z "${VIRTUAL_ENV:-}" ]; then
  echo "run.sh: warning: no virtual environment is active; the gate job installs into the first python on PATH" >&2
fi
command -v gitlab-ci-local >/dev/null || { echo "run.sh: gitlab-ci-local is not on PATH" >&2; exit 2; }
export PIP_DISABLE_PIP_VERSION_CHECK=1

stage=(--stage test)
args=()
for arg in "$@"; do
  if [ "$arg" = "--deploy" ]; then stage=(); else args+=("$arg"); fi
done
if [ ${#stage[@]} -eq 0 ]; then
  echo "run.sh: whole pipeline; apply runs if the Gate's job passes" >&2
else
  echo "run.sh: test stage only, plan and the gate; add --deploy to let apply run" >&2
fi

exec gitlab-ci-local --force-shell-executor ${stage[@]+"${stage[@]}"} \
  --variable CI_PROJECT_ID="$PILOT_PROJECT_ID" \
  --variable CI_PROJECT_DIR="$PWD" \
  --variable CI_JOB_TOKEN="$GL_TOKEN" \
  --variable TF_STATE_USERNAME="$GITLAB_USER" \
  --ignore-predefined-vars CI_PROJECT_ID,CI_PROJECT_DIR \
  ${args[@]+"${args[@]}"}
