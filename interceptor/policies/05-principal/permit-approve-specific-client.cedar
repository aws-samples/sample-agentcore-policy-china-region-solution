// Only one identity (the JWT "sub" claim) may approve claims.
permit (
  principal == AgentCore::OAuthUser::"{{PRINCIPAL_SUB}}",
  action == AgentCore::Action::"InsuranceAPI___approve_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
