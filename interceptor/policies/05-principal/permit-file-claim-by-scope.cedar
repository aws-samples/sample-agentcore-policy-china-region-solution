// JWT claims are string tags. Check hasTag before getTag.
permit (
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"InsuranceAPI___file_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  principal.hasTag("scope") &&
  principal.getTag("scope") like "*invoke:agentcore*"
};
