// Read-only lookups are always allowed.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___get_claim_status",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
