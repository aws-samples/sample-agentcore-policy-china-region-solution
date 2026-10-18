"""Shared helpers for the demo scripts. Configuration comes from ../config.env."""
import base64
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request

import boto3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_ROOT = os.path.join(ROOT, "interceptor", "policies")
CONFIG_FILE = os.environ.get("CEDAR_DEMO_CONFIG", os.path.join(ROOT, "config.env"))


def load_config(path=CONFIG_FILE):
    """Evaluate config.env with bash so ${VAR:-default} overrides from the environment work."""
    if not os.path.isfile(path):
        raise SystemExit(f"{path} not found: copy config.env.example to config.env and fill it in")
    out = subprocess.run(
        ["bash", "-c", f"set -a; source {json.dumps(path)}; env -0"],
        check=True, capture_output=True, text=True,
    ).stdout
    env = dict(item.split("=", 1) for item in out.split("\0") if "=" in item)
    keys = [line.split("=", 1)[0] for line in open(path) if re.match(r"^[A-Z][A-Z0-9_]*=", line)]
    return {k: env.get(k, "") for k in keys}


CFG = load_config()
PREFIX = CFG["STACK_PREFIX"]
STACKS = {
    "artifacts": f"{PREFIX}-artifacts",
    "gateway": f"{PREFIX}-gateway",
    "engine": f"{PREFIX}-policy-engine",
}
REGIONS = {
    "cn": (CFG["CN_PROFILE"], CFG["CN_REGION"]),
    "global": (CFG["GLOBAL_PROFILE"], CFG["GLOBAL_REGION"]),
}


def global_enabled():
    return CFG.get("ENABLE_GLOBAL", "false").lower() == "true"


def session(which):
    profile, region = REGIONS[which]
    return boto3.Session(profile_name=profile or None, region_name=region)


def stack_outputs(sess, stack):
    stacks = sess.client("cloudformation").describe_stacks(StackName=stack)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def stack_parameter(sess, stack, key):
    stacks = sess.client("cloudformation").describe_stacks(StackName=stack)["Stacks"]
    return {p["ParameterKey"]: p.get("ParameterValue", "") for p in stacks[0].get("Parameters", [])}.get(key, "")


def scenario_files(scenario):
    folder = os.path.join(POLICY_ROOT, scenario)
    if not os.path.isdir(folder):
        raise SystemExit(f"unknown scenario {scenario!r}; choose from {scenarios()}")
    return [os.path.join(folder, f) for f in sorted(os.listdir(folder)) if f.endswith(".cedar")]


def scenarios():
    return sorted(d for d in os.listdir(POLICY_ROOT) if os.path.isdir(os.path.join(POLICY_ROOT, d)))


def render_policy(text, gateway_arn, principal_sub):
    return text.replace("{{GATEWAY_ARN}}", gateway_arn).replace("{{PRINCIPAL_SUB}}", principal_sub)


def client_secret():
    """OIDC_CLIENT_SECRET from the environment, else the secret stored by the China stack.

    The value is only used in-process to request a token; it is never printed.
    """
    if os.environ.get("OIDC_CLIENT_SECRET"):
        return os.environ["OIDC_CLIENT_SECRET"]
    sess = session("cn")
    arn = stack_outputs(sess, STACKS["gateway"]).get("ClientSecretArn")
    if not arn:
        raise SystemExit("no ClientSecretArn output on the China stack; run scripts/deploy.sh first")
    return sess.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]


def token_endpoint():
    with urllib.request.urlopen(CFG["OIDC_DISCOVERY_URL"], timeout=20) as resp:
        return json.load(resp)["token_endpoint"]


def access_token(secret=None):
    """client_credentials grant against the configured OIDC provider."""
    form = {
        "grant_type": "client_credentials",
        "client_id": CFG["OIDC_CLIENT_ID"],
        "client_secret": secret if secret is not None else client_secret(),
    }
    if CFG.get("OIDC_AUDIENCE"):
        form["audience"] = CFG["OIDC_AUDIENCE"]  # Auth0 and several other providers
    if CFG.get("OIDC_SCOPE"):
        form["scope"] = CFG["OIDC_SCOPE"]
    req = urllib.request.Request(
        token_endpoint(), data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)["access_token"]
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise SystemExit(f"token request failed: HTTP {e.code} {detail}") from None


def jwt_claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
