// forbid always wins over permit: delete_claim is blocked for everyone.
forbid (
  principal,
  action == AgentCore::Action::"InsuranceAPI___delete_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
