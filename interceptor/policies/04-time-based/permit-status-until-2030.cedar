// Absolute window: status lookups are allowed until 2030-01-01 UTC.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___get_claim_status",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  context.system.now < datetime("2030-01-01T00:00:00Z")
};
