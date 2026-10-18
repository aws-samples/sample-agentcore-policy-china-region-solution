import base64
import json
from datetime import datetime, timezone

import cedar_mapping as cm


def fake_jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


SCHEMA = {
    "type": "object",
    "properties": {
        "amount": {"type": "number"},
        "months": {"type": "integer"},
        "ok": {"type": "boolean"},
        "name": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "risk": {"type": "object", "properties": {"priorClaims": {"type": "integer"}, "score": {"type": "number"}}},
    },
}


def test_number_schema_wins_over_json_int():
    assert cm.coerce_arguments({"amount": 500}, SCHEMA)["amount"] == {"__extn": {"fn": "decimal", "arg": "500.0"}}


def test_decimal_formatting_and_rounding():
    assert cm.coerce_arguments({"amount": 1234.5678}, SCHEMA)["amount"]["__extn"]["arg"] == "1234.5678"
    assert cm.coerce_arguments({"amount": 0.123456}, SCHEMA)["amount"]["__extn"]["arg"] == "0.1235"


def test_scalar_and_container_types():
    out = cm.coerce_arguments(
        {"months": 12, "ok": True, "name": "x", "tags": ["a", "b"], "risk": {"priorClaims": 2, "score": 1.5}}, SCHEMA
    )
    assert out["months"] == 12 and out["ok"] is True and out["name"] == "x"
    assert out["tags"] == ["a", "b"]
    assert out["risk"] == {"priorClaims": 2, "score": {"__extn": {"fn": "decimal", "arg": "1.5"}}}


def test_null_omitted_and_unknown_fields_inferred():
    out = cm.coerce_arguments({"name": None, "extraF": 2.5, "extraI": 3, "extraB": False}, SCHEMA)
    assert "name" not in out
    assert out["extraF"] == {"__extn": {"fn": "decimal", "arg": "2.5"}}
    assert out["extraI"] == 3 and out["extraB"] is False


def test_no_schema_infers_everything():
    assert cm.coerce_arguments({"a": 1, "b": 1.25}, None) == {"a": 1, "b": {"__extn": {"fn": "decimal", "arg": "1.25"}}}


def test_principal_tags_are_strings():
    uid, ent = cm.principal_entity({"sub": "a@clients", "exp": 1, "flag": True, "scope": ["x", "y"], "nil": None})
    assert uid == 'AgentCore::OAuthUser::"a@clients"'
    assert ent["uid"] == {"type": "AgentCore::OAuthUser", "id": "a@clients"}
    assert ent["tags"] == {"sub": "a@clients", "exp": "1", "flag": "true", "scope": '["x","y"]'}


def test_principal_anonymous_when_no_sub():
    uid, ent = cm.principal_entity({})
    assert uid == 'AgentCore::OAuthUser::"anonymous"' and ent["tags"] == {}


def test_decode_jwt_header_variants():
    tok = fake_jwt({"sub": "u1"})
    assert cm.decode_jwt_claims({"authorization": f"Bearer {tok}"})["sub"] == "u1"
    assert cm.decode_jwt_claims({"Authorization": f"bearer {tok}"})["sub"] == "u1"
    assert cm.decode_jwt_claims(None) == {}
    assert cm.decode_jwt_claims({}) == {}
    assert cm.decode_jwt_claims({"Authorization": "Bearer garbage"}) == {}
    assert cm.decode_jwt_claims({"Authorization": "Basic abc"}) == {}


def test_datetime_extn():
    now = datetime(2026, 10, 11, 10, 5, 7, 123, tzinfo=timezone.utc)
    assert cm.datetime_extn(now) == {"__extn": {"fn": "datetime", "arg": "2026-10-11T10:05:07Z"}}


def test_build_request_shape():
    now = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    req, ents = cm.build_request(
        "InsuranceAPI___file_claim", {"amount": 5}, {"sub": "u1", "role": "admin"}, "arn:aws-cn:gw", SCHEMA, now
    )
    assert req["principal"] == 'AgentCore::OAuthUser::"u1"'
    assert req["action"] == 'AgentCore::Action::"InsuranceAPI___file_claim"'
    assert req["resource"] == 'AgentCore::Gateway::"arn:aws-cn:gw"'
    assert req["context"]["input"]["amount"]["__extn"]["fn"] == "decimal"
    assert req["context"]["system"]["now"]["__extn"]["fn"] == "datetime"
    assert ents[0]["tags"]["role"] == "admin"


def test_deny_body_shape():
    # Shape observed from Policy in AgentCore (us-west-2) on a denied tools/call.
    b = cm.deny_body(7, "x")
    assert b == {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {"code": -32002, "message": "Tool Execution Denied: Tool call not allowed due to policy enforcement [x]"},
    }
