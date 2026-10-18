"""Mock InsuranceAPI Lambda target for AgentCore Gateway.

The gateway passes tool arguments as the event and the fully qualified tool
name (``<TargetName>___<tool>``) in ``context.client_context.custom``.
"""
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_claim_status(args):
    return {"claimId": args.get("claimId"), "status": "UNDER_REVIEW"}


def file_claim(args):
    return {
        "claimId": "C-NEW-1",
        "status": "FILED",
        "contractId": args.get("contractId"),
        "claimType": args.get("claimType"),
        "amount": args.get("amount"),
        "policyTermMonths": args.get("policyTermMonths"),
    }


def approve_claim(args):
    return {
        "claimId": args.get("claimId"),
        "approved": args.get("approved"),
        "approvedAmountCents": args.get("approvedAmountCents"),
    }


def disburse_payment(args):
    return {"claimId": args.get("claimId"), "status": "DISBURSED", "amountCents": args.get("amountCents")}


def delete_claim(args):
    return {"claimId": args.get("claimId"), "deleted": True}


TOOLS = {
    "get_claim_status": get_claim_status,
    "file_claim": file_claim,
    "approve_claim": approve_claim,
    "disburse_payment": disburse_payment,
    "delete_claim": delete_claim,
}


def lambda_handler(event, context):
    client_context = getattr(context, "client_context", None)
    custom = getattr(client_context, "custom", None) or {}
    full_name = custom.get("bedrockAgentCoreToolName", "")
    tool = full_name.split("___", 1)[-1] if full_name else ""
    logger.info(json.dumps({"tool": full_name, "arguments": event}))
    fn = TOOLS.get(tool)
    if fn is None:
        return {"error": f"unknown tool: {full_name or '<missing>'}"}
    return fn(event or {})
