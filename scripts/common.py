"""Shared helpers for the demo scripts. Configuration comes from ../config.env."""
import base64
import json
import os
import re
import urllib.parse
import urllib.request

import boto3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_ROOT = os.path.join(ROOT, "interceptor", "policies")
CONFIG_FILE = os.environ.get("CEDAR_DEMO_CONFIG", os.path.join(ROOT, "config.env"))


_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _strip_value(raw):
    """Apply bash quoting rules for a single assignment value.

    Returns (text, expand): single-quoted text is literal, everything else is expanded.
    An unquoted '#' that follows whitespace starts a comment.
    """
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        quote = raw[0]
        close = raw.find(quote, 1)
        if close < 0:
            raise SystemExit(f"config.env: unterminated quote in {raw!r}")
        return raw[1:close], quote == '"'
    return re.split(r"\s+#", raw, maxsplit=1)[0], True


def _expand(text, lookup):
    """Expand $NAME, ${NAME} and ${NAME:-default} (defaults may nest)."""
    if "$(" in text or "`" in text:
        raise SystemExit(f"config.env: unsupported shell syntax in {text!r}")
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch != "$":
            out.append(ch)
            i += 1
            continue
        if text[i + 1:i + 2] == "{":
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            if depth:
                raise SystemExit(f"config.env: unbalanced braces in {text!r}")
            inner = text[i + 2:j - 1]
            m = _NAME.match(inner)
            rest = inner[m.end():] if m else None
            if not m or (rest and not rest.startswith(":-")):
                raise SystemExit(f"config.env: unsupported expansion ${{{inner}}}")
            value = lookup(m.group(0))
            out.append(value if value else (_expand(rest[2:], lookup) if rest else ""))
            i = j
            continue
        m = _NAME.match(text, i + 1)
        if m:
            out.append(lookup(m.group(0)))
            i = m.end()
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def load_config(path=CONFIG_FILE):
    """Read config.env the way `source config.env` would for the syntax the example uses.

    Values already set in the environment win through ${VAR:-default}. No shell is run.
    """
    if not os.path.isfile(path):
        raise SystemExit(f"{path} not found: copy config.env.example to config.env and fill it in")
    cfg = {}
    lookup = lambda name: cfg[name] if name in cfg else os.environ.get(name, "")  # noqa: E731
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = _LINE.match(line.rstrip("\n"))
            if not m:
                continue
            text, expand = _strip_value(m.group(2))
            cfg[m.group(1)] = _expand(text, lookup) if expand else text
    return cfg


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
