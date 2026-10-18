#!/usr/bin/env bash
# One-command deployment. Usage: scripts/deploy.sh
#   China stack always; the global Policy in AgentCore control group when ENABLE_GLOBAL=true.
cd "$(dirname "$0")/.."
source scripts/lib.sh

# ---------------------------------------------------------------- preflight
log "Preflight checks"
command -v aws >/dev/null || die "AWS CLI v2 is required"
command -v python3 >/dev/null || die "python3 is required"
grep -q 'YOUR_' <<<"$OIDC_DISCOVERY_URL$OIDC_CLIENT_ID" && die "fill in OIDC_DISCOVERY_URL and OIDC_CLIENT_ID in config.env"
CN_ARN=$(cn sts get-caller-identity --query Arn --output text) || die "cannot use profile '$CN_PROFILE' in $CN_REGION"
[[ $CN_ARN == arn:aws-cn:* ]] || die "profile '$CN_PROFILE' is not an aws-cn (China) identity: $CN_ARN"
echo "China identity: $CN_ARN"
if [[ $ENABLE_GLOBAL == true ]]; then
  GL_ARN=$(gl sts get-caller-identity --query Arn --output text) || die "cannot use profile '$GLOBAL_PROFILE'"
  echo "Global identity: $GL_ARN"
fi
ensure_venv

# ---------------------------------------------------------------- client secret
SECRET_ARN=$(output cn "$GATEWAY_STACK" ClientSecretArn)
NEW_SECRET="${OIDC_CLIENT_SECRET:-}"
if [[ -z $NEW_SECRET && -z $SECRET_ARN ]]; then
  read -r -s -p "OIDC client secret for client ${OIDC_CLIENT_ID}: " NEW_SECRET; echo
  [[ -n $NEW_SECRET ]] || die "a client secret is required on first deployment"
fi

log "Requesting a test token from the identity provider"
SUB=$(OIDC_CLIENT_SECRET="$NEW_SECRET" $PY - <<'PY'
import os, sys
sys.path.insert(0, "scripts")
import common
secret = os.environ.get("OIDC_CLIENT_SECRET") or None
print(common.jwt_claims(common.access_token(secret))["sub"])
PY
) || die "could not get a token; check OIDC_* settings and the client secret"
echo "Token OK. Demo principal (sub claim): $SUB"

# ---------------------------------------------------------------- build
log "Building Lambda packages (arm64, Python 3.12)"
rm -rf build && mkdir -p build/interceptor
cp interceptor/*.py interceptor/tool_schema.json build/interceptor/
cp -r interceptor/policies build/interceptor/
python3 -m pip install -q --disable-pip-version-check -r interceptor/requirements.txt \
  --target build/interceptor --platform manylinux2014_aarch64 --implementation cp \
  --python-version 3.12 --only-binary=:all:

PARAMS_FILE=$(mktemp); chmod 600 "$PARAMS_FILE"; trap 'rm -f "$PARAMS_FILE"' EXIT

# write_params KEY=VALUE...  -> CloudFormation-style JSON file (keeps secrets off the command line)
write_params() {
  $PY - "$PARAMS_FILE" "$@" <<'PY'
import json, sys
path, pairs = sys.argv[1], sys.argv[2:]
json.dump([{"ParameterKey": k, "ParameterValue": v} for k, v in (p.split("=", 1) for p in pairs)], open(path, "w"))
PY
}

# deploy_stack <aws-wrapper> <bucket> <extra KEY=VALUE...>
deploy_gateway() {
  local aws=$1 bucket=$2; shift 2
  "$aws" cloudformation package --template-file infra/template.yaml --s3-bucket "$bucket" \
    --s3-prefix "$GATEWAY_STACK" --output-template-file build/packaged.yaml >/dev/null
  write_params OidcDiscoveryUrl="$OIDC_DISCOVERY_URL" OidcAudience="$OIDC_AUDIENCE" \
    GatewayName="${STACK_PREFIX}-gw" DemoPrincipalSub="$SUB" "$@"
  "$aws" cloudformation deploy --template-file build/packaged.yaml --stack-name "$GATEWAY_STACK" \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --no-fail-on-empty-changeset \
    --parameter-overrides "file://$PARAMS_FILE"
}

deploy_artifacts() { # <aws-wrapper>
  "$1" cloudformation deploy --template-file infra/artifacts.yaml --stack-name "$ARTIFACTS_STACK" \
    --no-fail-on-empty-changeset >/dev/null
  output "$1" "$ARTIFACTS_STACK" BucketName
}

# ---------------------------------------------------------------- China
log "China ($CN_REGION): artifacts bucket"
CN_BUCKET=$(deploy_artifacts cn)
FN=$(output cn "$GATEWAY_STACK" InterceptorFunctionName)
SCENARIO=01-allowlist
if [[ -n $FN ]]; then  # keep the scenario that is currently active
  SCENARIO=$(cn lambda get-function-configuration --function-name "$FN" \
    --query 'Environment.Variables.POLICY_SCENARIO' --output text)
fi
ARN=$(output cn "$GATEWAY_STACK" GatewayArn)
EXTRA=(EnableInterceptor=true PolicyScenario="$SCENARIO")
[[ -n $ARN ]] && EXTRA+=(InterceptorGatewayArn="$ARN")
[[ -n $NEW_SECRET ]] && EXTRA+=(OidcClientSecret="$NEW_SECRET")
log "China ($CN_REGION): gateway with Cedar interceptor (scenario $SCENARIO)"
deploy_gateway cn "$CN_BUCKET" "${EXTRA[@]}"
NEW_ARN=$(output cn "$GATEWAY_STACK" GatewayArn)
if [[ $NEW_ARN != "$ARN" ]]; then
  log "China: second pass to hand the gateway ARN to the interceptor"
  deploy_gateway cn "$CN_BUCKET" EnableInterceptor=true PolicyScenario="$SCENARIO" InterceptorGatewayArn="$NEW_ARN"
fi

# ---------------------------------------------------------------- global (optional)
if [[ $ENABLE_GLOBAL == true ]]; then
  log "Global ($GLOBAL_REGION): artifacts bucket and policy engine"
  GL_BUCKET=$(deploy_artifacts gl)
  gl cloudformation deploy --template-file infra/policy-engine.yaml --stack-name "$ENGINE_STACK" \
    --no-fail-on-empty-changeset >/dev/null
  ENGINE_ARN=$(output gl "$ENGINE_STACK" PolicyEngineArn)
  log "Global ($GLOBAL_REGION): gateway with Policy in AgentCore"
  deploy_gateway gl "$GL_BUCKET" EnableInterceptor=false PolicyEngineArn="$ENGINE_ARN"
  log "Global: loading scenario $SCENARIO into the policy engine"
  $PY scripts/switch_scenario.py "$SCENARIO" --region global
fi

log "Done"
echo "China gateway:  $(output cn "$GATEWAY_STACK" GatewayUrl)"
[[ $ENABLE_GLOBAL == true ]] && echo "Global gateway: $(output gl "$GATEWAY_STACK" GatewayUrl)"
echo
echo "Next: scripts/demo.sh            # run all five scenarios"
