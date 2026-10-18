from types import SimpleNamespace

import claims_tool


def ctx(tool):
    return SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": tool}))


def test_get_claim_status_returns_claim_and_status():
    out = claims_tool.lambda_handler({"claimId": "C-1"}, ctx("InsuranceAPI___get_claim_status"))
    assert out["claimId"] == "C-1"
    assert out["status"]


def test_file_claim_echoes_amount():
    out = claims_tool.lambda_handler(
        {"contractId": "K-1", "claimType": "auto", "amount": 500, "policyTermMonths": 12},
        ctx("InsuranceAPI___file_claim"),
    )
    assert out["status"] == "FILED" and out["amount"] == 500


def test_unknown_tool_returns_error():
    out = claims_tool.lambda_handler({}, ctx("InsuranceAPI___nope"))
    assert "error" in out


def test_missing_client_context_returns_error():
    out = claims_tool.lambda_handler({}, SimpleNamespace(client_context=None))
    assert "error" in out
