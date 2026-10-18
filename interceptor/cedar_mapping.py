"""Map an MCP tools/call request to a Cedar authorization request.

The mapping mirrors Policy in AgentCore:
  principal = AgentCore::OAuthUser::"<jwt sub>", every JWT claim as a string tag
  action    = AgentCore::Action::"<TargetName>___<tool>"
  resource  = AgentCore::Gateway::"<gateway arn>"
  context   = {"input": <tool arguments typed by the tool input schema>,
               "system": {"now": datetime}}
"""
import base64
import json
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

DENY_PREFIX = "Tool Execution Denied: Tool call not allowed due to policy enforcement"
# JSON-RPC error code that Policy in AgentCore returns for a denied tools/call.
DENY_ERROR_CODE = -32002
DEFAULT_DENY_REASON = "No policy applies to the request (denied by default)."

def _extn(fn, arg):
    return {"__extn": {"fn": fn, "arg": arg}}


def decimal_extn(value):
    """Cedar decimal: at most 4 fraction digits, always at least one."""
    try:
        d = Decimal(str(value)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    except InvalidOperation as exc:
        raise ValueError(f"not a number: {value!r}") from exc
    text = format(d, "f").rstrip("0")
    if text.endswith("."):
        text += "0"
    return _extn("decimal", text)


def datetime_extn(now):
    return _extn("datetime", now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


def _infer(value):
    if isinstance(value, bool) or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return decimal_extn(value)
    if isinstance(value, list):
        return [_infer(v) for v in value if v is not None]
    if isinstance(value, dict):
        return {k: _infer(v) for k, v in value.items() if v is not None}
    return value


def _coerce(value, schema):
    if value is None:
        return None
    stype = (schema or {}).get("type")
    if stype == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
        return decimal_extn(value)
    if stype == "integer" and isinstance(value, float) and value.is_integer():
        return int(value)
    if stype == "array" and isinstance(value, list):
        items = (schema or {}).get("items")
        return [_coerce(v, items) for v in value if v is not None]
    if stype == "object" and isinstance(value, dict):
        return coerce_arguments(value, schema)
    if stype is None:
        return _infer(value)
    return value


def coerce_arguments(args, input_schema):
    """Turn JSON tool arguments into Cedar JSON values; null members are omitted."""
    props = (input_schema or {}).get("properties") or {}
    out = {}
    for key, value in (args or {}).items():
        if value is None:
            continue
        out[key] = _coerce(value, props.get(key))
    return out


def _header(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return None


def decode_jwt_claims(headers):
    """Read JWT claims from the Authorization header without verifying it.

    The gateway's CUSTOM_JWT authorizer has already verified signature,
    issuer, audience and expiry before the interceptor runs.
    """
    auth = _header(headers, "authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return {}
    parts = auth.split(" ", 1)[1].strip().split(".")
    if len(parts) != 3:
        return {}
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, TypeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _tag_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (list, dict)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def principal_entity(claims):
    sub = claims.get("sub") if isinstance(claims.get("sub"), str) and claims.get("sub") else "anonymous"
    tags = {k: _tag_value(v) for k, v in claims.items() if v is not None}
    entity = {"uid": {"type": "AgentCore::OAuthUser", "id": sub}, "attrs": {}, "parents": [], "tags": tags}
    return f'AgentCore::OAuthUser::{json.dumps(sub, ensure_ascii=False)}', entity


def build_request(tool_full_name, args, claims, gateway_arn, input_schema, now):
    principal, entity = principal_entity(claims)
    request = {
        "principal": principal,
        "action": f"AgentCore::Action::{json.dumps(tool_full_name, ensure_ascii=False)}",
        "resource": f"AgentCore::Gateway::{json.dumps(gateway_arn, ensure_ascii=False)}",
        "context": {
            "input": coerce_arguments(args, input_schema),
            "system": {"now": datetime_extn(now)},
        },
    }
    return request, [entity]


def build_list_request(tool_full_name, claims, gateway_arn, now):
    """Request for tools/list filtering: principal and time known, tool arguments unknown."""
    principal, entity = principal_entity(claims)
    request = {
        "principal": principal,
        "action": f"AgentCore::Action::{json.dumps(tool_full_name, ensure_ascii=False)}",
        "resource": f"AgentCore::Gateway::{json.dumps(gateway_arn, ensure_ascii=False)}",
        "context": {
            "input": _extn("unknown", "input"),
            "system": {"now": datetime_extn(now)},
        },
    }
    return request, [entity]


def deny_body(request_id, reason):
    """Same JSON-RPC error Policy in AgentCore returns (observed in us-west-2)."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": DENY_ERROR_CODE, "message": f"{DENY_PREFIX} [{reason}]"},
    }


def utcnow():
    return datetime.now(timezone.utc)
