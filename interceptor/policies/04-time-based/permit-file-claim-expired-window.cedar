// Absolute window that is already over: filing was only open in January 2025.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___file_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  context.system.now >= datetime("2025-01-01T00:00:00Z") &&
  context.system.now < datetime("2025-02-01T00:00:00Z")
};
