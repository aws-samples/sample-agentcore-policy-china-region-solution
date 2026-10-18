// Any caller authenticated by the gateway's JWT authorizer.
permit (
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"InsuranceAPI___get_claim_status",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
);
