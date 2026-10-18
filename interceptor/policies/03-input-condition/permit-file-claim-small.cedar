// amount is a JSON Schema "number", so it is a Cedar decimal:
// compare it with decimal methods, not with < or >.
// claimType is a string, matched against an allowed set.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___file_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  context.input.amount.lessThanOrEqual(decimal("1000.00")) &&
  ["health", "auto"].contains(context.input.claimType)
};
