"""Every scenario's tests.json must hold when run through the interceptor."""
import base64
import glob
import json
import os
import re
from datetime import datetime, timezone

import pytest

import handler

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "interceptor", "policies")
GW = "arn:aws-cn:bedrock-agentcore:cn-north-1:111122223333:gateway/demo-abc"
SUB = "democlient0123456789@clients"
# Same claim names and value types as an Auth0 client_credentials access token.
CLAIMS = {
    "iss": "https://example.us.auth0.com/",
    "sub": SUB,
    "aud": "https://agentcore-cedar-demo",
    "iat": 1791767058,
    "exp": 1791853458,
    "scope": "invoke:agentcore",
    "gty": "client-credentials",
    "azp": "democlient0123456789",
}
TEN_UTC = datetime(2026, 10, 11, 10, 0, tzinfo=timezone.utc)
TWENTY_TWO_UTC = datetime(2026, 10, 11, 22, 0, tzinfo=timezone.utc)


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


def rows():
    for path in sorted(glob.glob(os.path.join(ROOT, "*", "tests.json"))):
        scenario = os.path.basename(os.path.dirname(path))
        for i, row in enumerate(json.load(open(path))):
            if row["expect"] == "TIME_09_17":
                yield pytest.param(scenario, row, TEN_UTC, "ALLOW", id=f"{scenario}-{i}-{row['tool']}-10h")
                yield pytest.param(scenario, row, TWENTY_TWO_UTC, "DENY", id=f"{scenario}-{i}-{row['tool']}-22h")
            else:
                yield pytest.param(scenario, row, TEN_UTC, row["expect"], id=f"{scenario}-{i}-{row['tool']}")


@pytest.mark.parametrize("scenario,row,now,expected", list(rows()))
def test_scenario_row(monkeypatch, scenario, row, now, expected):
    monkeypatch.setenv("GATEWAY_ARN", GW)
    monkeypatch.setenv("PRINCIPAL_SUB", SUB)
    monkeypatch.setenv("POLICY_SCENARIO", scenario)
    monkeypatch.setattr(handler, "now_provider", lambda: now)
    handler.reset_caches()
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": f"InsuranceAPI___{row['tool']}", "arguments": row["arguments"]}}
    event = {"interceptorInputVersion": "1.0",
             "mcp": {"gatewayRequest": {"body": body, "headers": {"Authorization": f"Bearer {jwt(CLAIMS)}"}}}}
    out = handler.lambda_handler(event, None)
    got = "DENY" if "transformedGatewayResponse" in out["mcp"] else "ALLOW"
    if got == "DENY":
        assert "interceptor error" not in out["mcp"]["transformedGatewayResponse"]["body"]["error"]["message"]
    assert got == expected


SCENARIOS = sorted(d for d in os.listdir(ROOT) if os.path.isdir(os.path.join(ROOT, d)))


def test_five_scenarios_with_tests():
    assert SCENARIOS == ["01-allowlist", "02-forbid-sensitive", "03-input-condition", "04-time-based", "05-principal"]
    for s in SCENARIOS:
        assert os.path.isfile(os.path.join(ROOT, s, "tests.json"))


@pytest.mark.parametrize("path", sorted(glob.glob(os.path.join(ROOT, "*", "*.cedar"))))
def test_policy_file_is_one_statement_scoped_to_gateway(path):
    text = open(path).read()
    stripped = re.sub(r"//[^\n]*", "", text)
    assert len(re.findall(r"\b(permit|forbid)\s*\(", stripped)) == 1
    assert 'resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"' in stripped


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("now", [TEN_UTC, TWENTY_TWO_UTC], ids=["10h", "22h"])
def test_tools_list_matches_policy_observation(monkeypatch, scenario, now):
    """tools_list.json holds what Policy in AgentCore listed for the Auth0 demo token."""
    monkeypatch.setenv("GATEWAY_ARN", GW)
    monkeypatch.setenv("PRINCIPAL_SUB", SUB)
    monkeypatch.setenv("POLICY_SCENARIO", scenario)
    monkeypatch.setattr(handler, "now_provider", lambda: now)
    handler.reset_caches()
    tools = [t["name"] for t in json.load(open(os.path.join(ROOT, "..", "tool_schema.json")))]
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    resp = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": f"InsuranceAPI___{t}"} for t in tools]}}
    event = {"interceptorInputVersion": "1.0", "mcp": {
        "gatewayRequest": {"body": req, "headers": {"Authorization": f"Bearer {jwt(CLAIMS)}"}},
        "gatewayResponse": {"statusCode": 200, "body": resp}}}
    out = handler.lambda_handler(event, None)
    got = sorted(t["name"].split("___", 1)[1] for t in out["mcp"]["transformedGatewayResponse"]["body"]["result"]["tools"])
    assert got == json.load(open(os.path.join(ROOT, scenario, "tools_list.json")))
