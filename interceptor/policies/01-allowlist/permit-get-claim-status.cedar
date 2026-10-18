// Allow-list: only the read-only status lookup is permitted.
// Every other tool is denied by default.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___get_claim_status",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
