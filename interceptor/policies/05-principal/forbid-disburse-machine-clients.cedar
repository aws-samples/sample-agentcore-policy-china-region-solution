// Machine-to-machine tokens (client_credentials grant) may never move money.
forbid (
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"InsuranceAPI___disburse_payment",
  resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
)
when {
  principal.hasTag("gty") &&
  principal.getTag("gty") == "client-credentials"
};
