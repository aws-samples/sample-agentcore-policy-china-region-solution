// approvedAmountCents is a JSON Schema "integer", so it is a Cedar Long.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___approve_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  context.input.approvedAmountCents < 100000
};
