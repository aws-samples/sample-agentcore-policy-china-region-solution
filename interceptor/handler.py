"""AgentCore Gateway REQUEST interceptor that enforces Cedar policies.

China regions have AgentCore Gateway but not Policy in AgentCore. This Lambda
evaluates the same Cedar policies locally with cedarpy (the Rust Cedar engine)
and short-circuits denied tools/call requests with the same error shape that
Policy in AgentCore returns.

Environment:
  GATEWAY_ARN      ARN of the gateway; used as the Cedar resource and to render policies
  POLICY_SCENARIO  folder under ./policies holding one Cedar policy per *.cedar file
  PRINCIPAL_SUB    optional value substituted for {{PRINCIPAL_SUB}} in policies
"""
import json
import logging
import os
import re

from cedarpy import Decision, is_authorized, is_authorized_partial, policies_to_json_str

import cedar_mapping as cm

logger = logging.getLogger()
logger.setLevel(logging.INFO)

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_ROOT = os.path.join(HERE, "policies")
SCHEMA_FILE = os.path.join(HERE, "tool_schema.json")
SCENARIO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")

now_provider = cm.utcnow
_policy_cache = {}
_schema_cache = None


def reset_caches():
    global _schema_cache
    _policy_cache.clear()
    _schema_cache = None


def load_tool_schemas():
    """Return {short tool name: inputSchema} from the bundled tool_schema.json."""
    global _schema_cache
    if _schema_cache is None:
        with open(SCHEMA_FILE, encoding="utf-8") as f:
            _schema_cache = {t["name"]: t.get("inputSchema") for t in json.load(f)}
    return _schema_cache


def render(text, gateway_arn, principal_sub):
    return text.replace("{{GATEWAY_ARN}}", gateway_arn).replace("{{PRINCIPAL_SUB}}", principal_sub)


def load_policies(scenario, gateway_arn, principal_sub):
    """Return (policy text, {cedar policy id: file stem}). One policy per file."""
    key = (scenario, gateway_arn, principal_sub)
    if key in _policy_cache:
        return _policy_cache[key]
    if not scenario or not SCENARIO_RE.match(scenario):
        raise ValueError(f"invalid POLICY_SCENARIO {scenario!r}")
    folder = os.path.join(POLICY_ROOT, scenario)
    if not os.path.isdir(folder):
        raise ValueError(f"unknown POLICY_SCENARIO {scenario!r}")
    files = sorted(f for f in os.listdir(folder) if f.endswith(".cedar"))
    if not files:
        raise ValueError(f"no .cedar files in scenario {scenario!r}")
    texts, names = [], {}
    for i, name in enumerate(files):
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            text = render(f.read(), gateway_arn, principal_sub)
        count = len(json.loads(policies_to_json_str(text))["staticPolicies"])
        if count != 1:
            raise ValueError(f"{name}: expected exactly one policy, found {count}")
        texts.append(text)
        names[f"policy{i}"] = name[: -len(".cedar")]
    result = ("\n".join(texts), names)
    _policy_cache[key] = result
    return result


def _allow(body):
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}


def _deny(request_id, reason):
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {"transformedGatewayResponse": {"statusCode": 200, "body": cm.deny_body(request_id, reason)}},
    }


def evaluate(body, headers, gateway_arn, scenario, principal_sub, now):
    """Return (decision 'ALLOW'|'DENY', reason text, log record)."""
    params = body.get("params") or {}
    tool_full = params.get("name") or ""
    args = params.get("arguments") or {}
    if not isinstance(args, dict):
        raise ValueError("tools/call arguments must be an object")
    short = tool_full.split("___", 1)[-1]
    schema = load_tool_schemas().get(short)
    claims = cm.decode_jwt_claims(headers)
    request, entities = cm.build_request(tool_full, args, claims, gateway_arn, schema, now)
    policies, names = load_policies(scenario, gateway_arn, principal_sub)
    result = is_authorized(request, policies, entities)
    reasons = [names.get(r, r) for r in result.diagnostics.reasons]
    errors = list(result.diagnostics.errors)
    allowed = result.decision == Decision.Allow
    if allowed:
        reason = ""
    elif reasons:
        reason = f"Policy evaluation denied due to {', '.join(reasons)}"
    else:
        reason = cm.DEFAULT_DENY_REASON
    record = {
        "decision": "ALLOW" if allowed else "DENY",
        "scenario": scenario,
        "principal": request["principal"],
        "action": request["action"],
        "policies": reasons,
        "errors": errors,
    }
    return record["decision"], reason, record


def visible_tools(tools, headers, gateway_arn, scenario, principal_sub, now):
    """Keep a tool unless Cedar can already decide Deny without knowing its arguments.

    Policy in AgentCore filters tools/list the same way: a tool is hidden only when
    no permit could apply, or a forbid applies, for this principal. Tools without the
    <target>___ prefix (for example the built-in search tool) are left alone.
    """
    claims = cm.decode_jwt_claims(headers)
    policies, _ = load_policies(scenario, gateway_arn, principal_sub)
    kept = []
    for tool in tools:
        name = tool.get("name", "") if isinstance(tool, dict) else ""
        if "___" not in name:
            kept.append(tool)
            continue
        request, entities = cm.build_list_request(name, claims, gateway_arn, now)
        result = is_authorized_partial(request, policies, entities)
        # Hide on a definite Deny, and on any evaluation error (fail closed).
        if result.decision != Decision.Deny and not list(result.diagnostics.errors or []):
            kept.append(tool)
    return kept


def _response(status, body):
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayResponse": {"statusCode": status, "body": body}}}


def handle_response(mcp):
    """RESPONSE interceptor: filter tools/list results; pass everything else through."""
    gateway_request = mcp.get("gatewayRequest") if isinstance(mcp.get("gatewayRequest"), dict) else {}
    request_body = gateway_request.get("body")
    response = mcp.get("gatewayResponse") if isinstance(mcp.get("gatewayResponse"), dict) else {}
    status, body = response.get("statusCode", 200), response.get("body")
    method = request_body.get("method") if isinstance(request_body, dict) else None
    result = body.get("result") if isinstance(body, dict) else None
    tools = result.get("tools") if isinstance(result, dict) else None
    if method != "tools/list" or not isinstance(tools, list):
        return _response(status, body)
    try:
        kept = visible_tools(
            tools,
            gateway_request.get("headers"),
            os.environ.get("GATEWAY_ARN", "") or _raise("GATEWAY_ARN is not set"),
            os.environ.get("POLICY_SCENARIO", ""),
            os.environ.get("PRINCIPAL_SUB", ""),
            now_provider(),
        )
    except Exception as exc:  # fail closed: list nothing
        logger.error(json.dumps({"listFilter": "ERROR", "error": f"{type(exc).__name__}: {exc}"}))
        kept = []
    logger.info(json.dumps({"listFilter": "OK", "total": len(tools), "visible": len(kept)}))
    filtered = dict(body, result=dict(result, tools=kept))
    return _response(status, filtered)


def _raise(message):
    raise ValueError(message)


def lambda_handler(event, context):
    mcp = (event or {}).get("mcp") or {}
    if mcp.get("gatewayResponse") is not None:
        try:
            return handle_response(mcp)
        except Exception as exc:  # never fail the Lambda; return the response unchanged
            logger.error(json.dumps({"responsePhase": "ERROR", "error": f"{type(exc).__name__}: {exc}"}))
            return {"interceptorOutputVersion": "1.0", "mcp": {}}
    gateway_request = mcp.get("gatewayRequest") or {}
    body = gateway_request.get("body")
    request_id = body.get("id") if isinstance(body, dict) else None
    try:
        if not isinstance(body, dict):
            raise ValueError("JSON-RPC batch or non-object body is not supported")
        method = body.get("method")
        if method is None:
            if "result" in body or "error" in body:  # client's reply to a server request
                return _allow(body)
            raise ValueError("JSON-RPC request without a method")
        if not isinstance(method, str):
            raise ValueError("JSON-RPC method must be a string")
        if method != "tools/call":
            if method.strip().lower() == "tools/call":
                raise ValueError(f"non-canonical method {method!r}")
            logger.info(json.dumps({"decision": "PASS", "method": method}))
            return _allow(body)
        gateway_arn = os.environ.get("GATEWAY_ARN", "")
        if not gateway_arn:
            raise ValueError("GATEWAY_ARN is not set")
        decision, reason, record = evaluate(
            body,
            gateway_request.get("headers"),
            gateway_arn,
            os.environ.get("POLICY_SCENARIO", ""),
            os.environ.get("PRINCIPAL_SUB", ""),
            now_provider(),
        )
        logger.info(json.dumps(record))
        return _allow(body) if decision == "ALLOW" else _deny(request_id, reason)
    except Exception as exc:  # fail closed on anything unexpected
        logger.error(json.dumps({"decision": "DENY", "error": f"{type(exc).__name__}: {exc}"}))
        return _deny(request_id, f"interceptor error: {type(exc).__name__}: {exc}")
