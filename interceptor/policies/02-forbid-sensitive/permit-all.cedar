// Baseline: every tool on this gateway is permitted.
permit (
  principal,
  action,
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
