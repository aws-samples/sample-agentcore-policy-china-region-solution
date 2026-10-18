import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import common  # noqa: E402
import demo  # noqa: E402


def test_classify_policy_deny():
    msg = {"error": {"code": -32002, "message": "Tool Execution Denied: Tool call not allowed due to policy enforcement [x]"}}
    assert demo.classify(msg) == ("DENY", msg["error"]["message"])


def test_classify_allow_and_errors():
    assert demo.classify({"result": {"content": [{"type": "text", "text": "{}"}]}})[0] == "ALLOW"
    assert demo.classify({"result": {"isError": True, "content": [{"type": "text", "text": "boom"}]}})[0] == "ERROR"
    assert demo.classify({"error": {"code": -32602}})[0] == "ERROR"
    assert demo.classify({"httpError": 401, "text": "no"})[0] == "ERROR"


def test_time_expectation_edges():
    row = {"expect": "TIME_09_17"}
    at = lambda h, m: datetime(2026, 1, 1, h, m, tzinfo=timezone.utc)
    assert demo.expected(row, at(8, 59)) == "DENY"
    assert demo.expected(row, at(9, 0)) == "ALLOW"
    assert demo.expected(row, at(17, 0)) == "ALLOW"
    assert demo.expected(row, at(17, 1)) == "DENY"
    assert demo.expected({"expect": "DENY"}, at(10, 0)) == "DENY"


def test_render_policy_fills_placeholders():
    assert common.render_policy('"{{GATEWAY_ARN}}" "{{PRINCIPAL_SUB}}"', "arn:x", "u1") == '"arn:x" "u1"'


def test_client_secret_prefers_environment(monkeypatch):
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "from-env")
    assert common.client_secret() == "from-env"


def test_stack_names_follow_prefix():
    assert common.STACKS == {"artifacts": "cedar-demo-artifacts", "gateway": "cedar-demo-gateway",
                             "engine": "cedar-demo-policy-engine"}


def test_missing_config_file_explains_what_to_do(tmp_path):
    import pytest
    with pytest.raises(SystemExit, match="config.env.example"):
        common.load_config(str(tmp_path / "config.env"))


def test_jwt_claims_decodes_payload():
    import base64, json
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    assert common.jwt_claims(f"{enc({'alg': 'RS256'})}.{enc({'sub': 'abc'})}.sig") == {"sub": "abc"}


import switch_scenario  # noqa: E402


def test_findings_only_detection():
    assert switch_scenario.is_findings_only(["Overly Permissive: x", "Overly Restrictive: y"])
    assert not switch_scenario.is_findings_only([])
    assert not switch_scenario.is_findings_only(["Overly Permissive: x", "unexpected type: expected Long but saw decimal"])


class FakeClient:
    """Minimal bedrock-agentcore-control stand-in driven by a list of GetPolicy outcomes."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.deleted = []

    def get_policy(self, policyEngineId, policyId):
        from botocore.exceptions import ClientError

        nxt = self.outcomes.pop(0) if self.outcomes else "GONE"
        if nxt == "GONE":
            raise ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, "GetPolicy")
        return {"policyId": policyId, "status": nxt}

    def delete_policy(self, policyEngineId, policyId):
        self.deleted.append(policyId)


def test_wait_retries_not_found_right_after_create(monkeypatch):
    monkeypatch.setattr(switch_scenario.time, "sleep", lambda s: None)
    c = FakeClient(["GONE", "CREATING", "ACTIVE"])
    assert switch_scenario.wait_policy(c, "e", "p", "ACTIVE")["status"] == "ACTIVE"


def test_delete_waits_for_creating_to_settle(monkeypatch):
    monkeypatch.setattr(switch_scenario.time, "sleep", lambda s: None)
    c = FakeClient(["CREATING", "CREATING", "ACTIVE", "DELETING", "GONE"])
    switch_scenario.delete_policy(c, "e", "p")
    assert c.deleted == ["p"] and c.outcomes == []


def test_delete_of_missing_policy_is_a_no_op(monkeypatch):
    monkeypatch.setattr(switch_scenario.time, "sleep", lambda s: None)
    c = FakeClient(["GONE"])
    switch_scenario.delete_policy(c, "e", "p")
    assert c.deleted == []


def test_create_falls_back_only_for_findings(monkeypatch):
    monkeypatch.setattr(switch_scenario.time, "sleep", lambda s: None)

    class C(FakeClient):
        def __init__(self, first_status, reasons):
            super().__init__([])
            self.first, self.reasons, self.modes = first_status, reasons, []

        def create_policy(self, **kw):
            self.modes.append(kw["validationMode"])
            ok = len(self.modes) > 1
            self.outcomes = ["ACTIVE"] if ok else [self.first, "GONE"]
            return {"policyId": f"p{len(self.modes)}"}

        def get_policy(self, policyEngineId, policyId):
            p = super().get_policy(policyEngineId, policyId)
            if p["status"].endswith("FAILED"):
                p["statusReasons"] = self.reasons
            return p

    c = C("CREATE_FAILED", ["Overly Permissive: x"])
    assert switch_scenario.create(c, "e", "n", "permit(principal,action,resource);", "d") == "IGNORE_ALL_FINDINGS"
    assert c.modes == ["FAIL_ON_ANY_FINDINGS", "IGNORE_ALL_FINDINGS"]

    import pytest
    c = C("CREATE_FAILED", ["unexpected type: expected Long but saw decimal"])
    with pytest.raises(SystemExit):
        switch_scenario.create(c, "e", "n", "x", "d")
    assert c.modes == ["FAIL_ON_ANY_FINDINGS"]
