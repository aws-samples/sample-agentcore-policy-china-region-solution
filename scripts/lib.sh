# Shared shell helpers. Source from the repo root.
set -euo pipefail
export AWS_PAGER=""
[[ -f config.env ]] || { echo "config.env not found: cp config.env.example config.env, then edit it" >&2; exit 1; }
set -a; source config.env; set +a

ARTIFACTS_STACK="${STACK_PREFIX}-artifacts"
GATEWAY_STACK="${STACK_PREFIX}-gateway"
ENGINE_STACK="${STACK_PREFIX}-policy-engine"
PY=.venv/bin/python

cn()  { aws --profile "$CN_PROFILE" --region "$CN_REGION" "$@"; }
gl()  { aws --profile "$GLOBAL_PROFILE" --region "$GLOBAL_REGION" "$@"; }
log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# output <aws-wrapper> <stack> <key>   prints the output value or nothing
output() {
  local v
  v=$("$1" cloudformation describe-stacks --stack-name "$2" \
        --query "Stacks[0].Outputs[?OutputKey=='$3'].OutputValue" --output text 2>/dev/null || true)
  [[ $v == None ]] && v=""
  printf '%s' "$v"
}

stack_exists() { "$1" cloudformation describe-stacks --stack-name "$2" >/dev/null 2>&1; }

ensure_venv() {
  if [[ ! -x $PY ]]; then
    log "Creating Python virtual environment for the helper scripts"
    python3 -m venv .venv
  fi
  $PY -m pip install -q --disable-pip-version-check -r scripts/requirements.txt
}
