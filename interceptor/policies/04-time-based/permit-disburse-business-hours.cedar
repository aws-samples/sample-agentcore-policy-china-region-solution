// Payments only between 09:00 and 17:00 UTC, every day.
permit (
  principal,
  action == AgentCore::Action::"InsuranceAPI___disburse_payment",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  duration("9h") <= context.system.now.toTime() &&
  context.system.now.toTime() <= duration("17h")
};
