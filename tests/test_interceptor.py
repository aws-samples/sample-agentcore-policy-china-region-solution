import base64
import json
from datetime import datetime, timezone

import pytest

import handler

GW = "arn:aws-cn:bedrock-agentcore:cn-north-1:111122223333:gateway/demo-abc"
SUB = "client-1@clients"


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


def event(method, params=None, headers=None, rid=1):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    req = {"path": "/mcp", "httpMethod": "POST", "body": body}
    if headers is not None:
        req["headers"] = headers
    return {"interceptorInputVersion": "1.0", "mcp": {"rawGatewayRequest": {"body": json.dumps(body)}, "gatewayRequest": req}}


def call(tool, args, headers="default", rid=1):
    if headers == "default":
        headers = {"Authorization": f"Bearer {jwt({'sub': SUB, 'scope': 'invoke:agentcore'})}"}
    return handler.lambda_handler(event("tools/call", {"name": f"InsuranceAPI___{tool}", "arguments": args}, headers, rid), None)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GATEWAY_ARN", GW)
    monkeypatch.setenv("PRINCIPAL_SUB", SUB)
    monkeypatch.setenv("POLICY_SCENARIO", "01-allowlist")
    monkeypatch.setattr(handler, "now_provider", lambda: datetime(2026, 10, 11, 10, 0, tzinfo=timezone.utc))
    handler.reset_caches()


def is_allow(out):
    m = out["mcp"]
    return "transformedGatewayRequest" in m and "transformedGatewayResponse" not in m


def deny_text(out):
    body = out["mcp"]["transformedGatewayResponse"]["body"]
    assert body["error"]["code"] == -32002
    return body["error"]["message"]


def test_tools_list_passes_through_unchanged():
    ev = event("tools/list")
    out = handler.lambda_handler(ev, None)
    assert out["interceptorOutputVersion"] == "1.0"
    assert is_allow(out)
    assert out["mcp"]["transformedGatewayRequest"]["body"] == ev["mcp"]["gatewayRequest"]["body"]


@pytest.mark.parametrize("method", ["initialize", "notifications/initialized", "ping"])
def test_non_tool_methods_pass_through(method):
    assert is_allow(handler.lambda_handler(event(method), None))


def test_allowlist_permits_status_lookup():
    out = call("get_claim_status", {"claimId": "C-1"})
    assert is_allow(out)
    assert out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"] == {"claimId": "C-1"}


def test_allowlist_denies_other_tool_by_default():
    out = call("file_claim", {"contractId": "K", "claimType": "auto", "amount": 1, "policyTermMonths": 1}, rid=42)
    assert out["mcp"]["transformedGatewayResponse"]["statusCode"] == 200
    assert out["mcp"]["transformedGatewayResponse"]["body"]["id"] == 42
    assert "denied by default" in deny_text(out)


def test_forbid_wins(monkeypatch):
    monkeypatch.setenv("POLICY_SCENARIO", "02-forbid-sensitive")
    assert is_allow(call("approve_claim", {"claimId": "C", "approved": True, "approvedAmountCents": 1}))
    text = deny_text(call("delete_claim", {"claimId": "C"}))
    # Policy in AgentCore wording: "Policy evaluation denied due to <policy id>"
    assert text.endswith("[Policy evaluation denied due to forbid-delete-claim]")


def test_unknown_scenario_fails_closed(monkeypatch):
    monkeypatch.setenv("POLICY_SCENARIO", "does-not-exist")
    assert "interceptor error" in deny_text(call("get_claim_status", {"claimId": "C"}))


def test_missing_gateway_arn_fails_closed(monkeypatch):
    monkeypatch.delenv("GATEWAY_ARN")
    assert "interceptor error" in deny_text(call("get_claim_status", {"claimId": "C"}))


def test_no_authorization_header_still_evaluated():
    assert is_allow(call("get_claim_status", {"claimId": "C"}, headers=None))
    assert "denied by default" in deny_text(call("delete_claim", {"claimId": "C"}, headers=None))


def test_batch_body_fails_closed():
    ev = event("tools/call", {"name": "InsuranceAPI___get_claim_status", "arguments": {}})
    ev["mcp"]["gatewayRequest"]["body"] = [ev["mcp"]["gatewayRequest"]["body"]]
    assert "interceptor error" in deny_text(handler.lambda_handler(ev, None))


def test_unexpected_exception_fails_closed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaput")

    monkeypatch.setattr(handler.cm, "build_request", boom)
    assert "interceptor error" in deny_text(call("get_claim_status", {"claimId": "C"}))


ALL_TOOLS = ["get_claim_status", "file_claim", "approve_claim", "disburse_payment", "delete_claim"]


def response_event(req_body, resp_body, headers="default", status=200):
    if headers == "default":
        headers = {"Authorization": f"Bearer {jwt({'sub': SUB, 'scope': 'invoke:agentcore', 'gty': 'client-credentials'})}"}
    ev = event(req_body["method"], req_body.get("params"), headers, req_body.get("id", 1))
    ev["mcp"]["gatewayResponse"] = {"statusCode": status, "body": resp_body}
    return ev


def tools_list_response(names):
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": f"InsuranceAPI___{n}", "inputSchema": {}} for n in names]}}


def listed(out):
    body = out["mcp"]["transformedGatewayResponse"]["body"]
    return [t["name"].split("___", 1)[1] for t in body["result"]["tools"]]


def test_response_filters_tools_list_like_policy(monkeypatch):
    monkeypatch.setenv("POLICY_SCENARIO", "05-principal")
    out = handler.lambda_handler(response_event({"method": "tools/list", "id": 1}, tools_list_response(ALL_TOOLS)), None)
    assert out["mcp"]["transformedGatewayResponse"]["statusCode"] == 200
    assert listed(out) == ["get_claim_status", "file_claim", "approve_claim"]


def test_response_keeps_tools_without_target_prefix(monkeypatch):
    resp = tools_list_response(["get_claim_status"])
    resp["result"]["tools"].append({"name": "x_amz_bedrock_agentcore_search", "inputSchema": {}})
    out = handler.lambda_handler(response_event({"method": "tools/list", "id": 1}, resp), None)
    names = [t["name"] for t in out["mcp"]["transformedGatewayResponse"]["body"]["result"]["tools"]]
    assert names == ["InsuranceAPI___get_claim_status", "x_amz_bedrock_agentcore_search"]


def test_response_passthrough_for_other_methods():
    resp = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "{}"}]}}
    req = {"method": "tools/call", "id": 3, "params": {"name": "InsuranceAPI___get_claim_status", "arguments": {}}}
    out = handler.lambda_handler(response_event(req, resp, status=200), None)
    assert out["mcp"]["transformedGatewayResponse"] == {"statusCode": 200, "body": resp}


def test_response_filter_error_hides_every_tool(monkeypatch):
    monkeypatch.setenv("POLICY_SCENARIO", "does-not-exist")
    out = handler.lambda_handler(response_event({"method": "tools/list", "id": 1}, tools_list_response(ALL_TOOLS)), None)
    assert listed(out) == []


# --- final review fixes -------------------------------------------------------

@pytest.mark.parametrize("bad_result", [[1, 2], "text", 5])
def test_response_with_non_dict_result_does_not_crash(bad_result):
    resp = {"jsonrpc": "2.0", "id": 2, "result": bad_result}
    out = handler.lambda_handler(response_event({"method": "tools/list", "id": 2}, resp), None)
    assert out["mcp"]["transformedGatewayResponse"]["body"] == resp


def test_response_with_non_dict_gateway_response_does_not_crash():
    ev = response_event({"method": "tools/list", "id": 2}, {})
    ev["mcp"]["gatewayResponse"] = "garbage"
    out = handler.lambda_handler(ev, None)
    assert out["interceptorOutputVersion"] == "1.0"


@pytest.mark.parametrize("method", ["Tools/Call", "tools/call ", " TOOLS/CALL"])
def test_tools_call_lookalike_methods_are_denied(method):
    ev = event(method, {"name": "InsuranceAPI___delete_claim", "arguments": {"claimId": "C"}})
    assert "interceptor error" in deny_text(handler.lambda_handler(ev, None))


def test_request_without_method_is_denied():
    ev = event("x", {"name": "InsuranceAPI___delete_claim", "arguments": {}})
    del ev["mcp"]["gatewayRequest"]["body"]["method"]
    assert "interceptor error" in deny_text(handler.lambda_handler(ev, None))


def test_client_jsonrpc_response_without_method_passes_through():
    ev = event("x")
    ev["mcp"]["gatewayRequest"]["body"] = {"jsonrpc": "2.0", "id": "elicit-1", "result": {"action": "accept"}}
    assert is_allow(handler.lambda_handler(ev, None))


def test_list_filter_hides_tool_when_partial_eval_errors(monkeypatch):
    class R:
        decision = handler.Decision.NoDecision

        class diagnostics:
            errors = ["failed to build request"]

    monkeypatch.setenv("POLICY_SCENARIO", "02-forbid-sensitive")
    monkeypatch.setattr(handler, "is_authorized_partial", lambda *a, **k: R())
    out = handler.lambda_handler(response_event({"method": "tools/list", "id": 1}, tools_list_response(ALL_TOOLS)), None)
    assert listed(out) == []


def test_non_ascii_tool_name_builds_a_valid_request():
    out = call("get_claim_statusé", {"claimId": "C"})
    assert "denied by default" in deny_text(out)
