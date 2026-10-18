// Only tokens carrying role=admin may delete. The demo token has no role claim.
permit (
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"InsuranceAPI___delete_claim",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  principal.hasTag("role") &&
  principal.getTag("role") == "admin"
};
