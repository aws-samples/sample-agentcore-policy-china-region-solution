import os
import sys

import pytest
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
    """Minimal bedrock-agentcore-control stand-in driven by a list of GetPolicy outcomes.

    When the list runs out the last outcome repeats. "GONE" means ResourceNotFound.
    """

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.last = "GONE"
        self.deleted = []
        self.calls = 0

    def _not_found(self, op):
        from botocore.exceptions import ClientError
        return ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, op)

    def get_policy(self, policyEngineId, policyId):
        self.calls += 1
        if self.outcomes:
            self.last = self.outcomes.pop(0)
        if self.last == "GONE":
            raise self._not_found("GetPolicy")
        return {"policyId": policyId, "status": self.last}

    def delete_policy(self, policyEngineId, policyId):
        if self.last == "GONE":
            raise self._not_found("DeletePolicy")
        self.deleted.append(policyId)


@pytest.fixture(autouse=False)
def fast_poll(monkeypatch):
    monkeypatch.setattr(switch_scenario, "POLL_SECONDS", 0)


def test_wait_retries_not_found_right_after_create(fast_poll):
    c = FakeClient(["GONE", "CREATING", "ACTIVE"])
    assert switch_scenario.wait_policy(c, "e", "p")["status"] == "ACTIVE"


def test_wait_returns_failed_policy_for_inspection(fast_poll):
    c = FakeClient(["CREATING", "CREATE_FAILED"])
    assert switch_scenario.wait_policy(c, "e", "p")["status"] == "CREATE_FAILED"


def test_delete_waits_for_creating_to_settle(fast_poll):
    c = FakeClient(["CREATING", "CREATING", "ACTIVE", "DELETING", "GONE"])
    switch_scenario.delete_policy(c, "e", "p")
    assert c.deleted == ["p"] and c.outcomes == []


def test_delete_of_missing_policy_is_a_no_op(fast_poll):
    c = FakeClient(["GONE"])
    switch_scenario.delete_policy(c, "e", "p")
    assert c.deleted == []


def test_wait_gives_up_after_max_attempts(fast_poll, monkeypatch):
    monkeypatch.setattr(switch_scenario, "MAX_ATTEMPTS", 3)
    c = FakeClient(["CREATING"])
    with pytest.raises(SystemExit, match="timed out|Max attempts"):
        switch_scenario.wait_policy(c, "e", "p")
    assert c.calls == 3


def test_no_sleep_calls_in_switch_scenario():
    src = open(switch_scenario.__file__, encoding="utf-8").read()
    assert "time.sleep" not in src


def test_create_falls_back_only_for_findings(fast_poll):

    class C(FakeClient):
        def __init__(self, first_status, reasons):
            super().__init__([])
            self.first, self.reasons, self.modes = first_status, reasons, []

        def create_policy(self, **kw):
            self.modes.append(kw["validationMode"])
            ok = len(self.modes) > 1
            self.outcomes = ["ACTIVE"] if ok else [self.first, self.first, "GONE"]
            return {"policyId": f"p{len(self.modes)}"}

        def get_policy(self, policyEngineId, policyId):
            p = super().get_policy(policyEngineId, policyId)
            if p["status"].endswith("FAILED"):
                p["statusReasons"] = self.reasons
            return p

    c = C("CREATE_FAILED", ["Overly Permissive: x"])
    assert switch_scenario.create(c, "e", "n", "permit(principal,action,resource);", "d") == "IGNORE_ALL_FINDINGS"
    assert c.modes == ["FAIL_ON_ANY_FINDINGS", "IGNORE_ALL_FINDINGS"]

    c = C("CREATE_FAILED", ["unexpected type: expected Long but saw decimal"])
    with pytest.raises(SystemExit):
        switch_scenario.create(c, "e", "n", "x", "d")
    assert c.modes == ["FAIL_ON_ANY_FINDINGS"]


# --- config.env parsing without a shell ---------------------------------------

def write_cfg(tmp_path, text):
    p = tmp_path / "config.env"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_config_defaults_and_env_override(tmp_path, monkeypatch):
    monkeypatch.delenv("A", raising=False)
    monkeypatch.setenv("B", "from-env")
    path = write_cfg(tmp_path, "A=${A:-alpha}   # trailing comment\nB=${B:-beta}\n# comment line\n\nC=plain\n")
    assert common.load_config(path) == {"A": "alpha", "B": "from-env", "C": "plain"}


def test_config_empty_env_value_uses_default(tmp_path, monkeypatch):
    monkeypatch.setenv("A", "")
    assert common.load_config(write_cfg(tmp_path, "A=${A:-alpha}\n")) == {"A": "alpha"}


def test_config_references_earlier_keys_and_nested_defaults(tmp_path, monkeypatch):
    for k in ("X", "Y", "Z"):
        monkeypatch.delenv(k, raising=False)
    path = write_cfg(tmp_path, "X=${X:-x1}\nY=${Y:-$X}\nZ=${Z:-${NOPE:-z-${X}}}\n")
    assert common.load_config(path) == {"X": "x1", "Y": "x1", "Z": "z-x1"}


def test_config_quotes(tmp_path, monkeypatch):
    monkeypatch.delenv("A", raising=False)
    path = write_cfg(tmp_path, "A='{{lit:$X}}'  # c\nB=\"two words\"\nU=https://x/y#frag\n")
    assert common.load_config(path) == {"A": "{{lit:$X}}", "B": "two words", "U": "https://x/y#frag"}


@pytest.mark.parametrize("value", ["$(whoami)", "`whoami`", "${A:=x}"])
def test_config_rejects_shell_features(tmp_path, value):
    with pytest.raises(SystemExit, match="unsupported"):
        common.load_config(write_cfg(tmp_path, f"A={value}\n"))


def test_example_config_parses_to_expected_keys(monkeypatch):
    for k in ("CN_PROFILE", "CN_REGION", "ENABLE_GLOBAL", "STACK_PREFIX"):
        monkeypatch.delenv(k, raising=False)
    cfg = common.load_config(os.path.join(common.ROOT, "config.env.example"))
    assert cfg["CN_REGION"] == "cn-north-1" and cfg["ENABLE_GLOBAL"] == "false"
    assert cfg["STACK_PREFIX"] == "cedar-demo" and cfg["OIDC_SCOPE"] == "invoke:agentcore"


def test_common_does_not_use_subprocess():
    src = open(common.__file__, encoding="utf-8").read()
    assert "subprocess" not in src
