#!/usr/bin/env bash
# Remove everything the demo created. Usage: scripts/destroy.sh
cd "$(dirname "$0")/.."
source scripts/lib.sh

delete_stack() { # <aws-wrapper> <stack>
  if stack_exists "$1" "$2"; then
    echo "deleting $2"
    "$1" cloudformation delete-stack --stack-name "$2"
    "$1" cloudformation wait stack-delete-complete --stack-name "$2"
  fi
}

empty_and_delete_artifacts() { # <aws-wrapper>
  local bucket
  bucket=$(output "$1" "$ARTIFACTS_STACK" BucketName)
  [[ -n $bucket ]] && "$1" s3 rm "s3://$bucket" --recursive --only-show-errors
  delete_stack "$1" "$ARTIFACTS_STACK"
}

log "China ($CN_REGION)"
delete_stack cn "$GATEWAY_STACK"
empty_and_delete_artifacts cn

if [[ $ENABLE_GLOBAL == true ]] || stack_exists gl "$ENGINE_STACK"; then
  log "Global ($GLOBAL_REGION)"
  ensure_venv
  delete_stack gl "$GATEWAY_STACK"
  if stack_exists gl "$ENGINE_STACK"; then
    $PY scripts/switch_scenario.py --clear-global
    delete_stack gl "$ENGINE_STACK"
  fi
  empty_and_delete_artifacts gl
fi
log "Done"
