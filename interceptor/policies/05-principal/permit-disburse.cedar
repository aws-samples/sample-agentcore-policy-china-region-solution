// Baseline permit for payments, narrowed by the forbid policy next to it.
permit (
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"InsuranceAPI___disburse_payment",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
