#pragma once

#include <cstdint>
#include <string_view>

namespace ipms::agent {

inline constexpr std::uint16_t k_default_agent_gateway_port = 9419;
inline constexpr std::string_view k_agent_gateway_alpn = "ipms-agent/1";

enum class GatewayDirection {
  agent_initiated_bidirectional,
};

enum class ServerMessageType {
  management_pack_assignment,
  inventory_collection_request,
  agent_update_manifest,
  certificate_rotation,
};

struct AgentGatewayConfig {
  std::string_view hostname;
  std::uint16_t port{k_default_agent_gateway_port};
  GatewayDirection direction{GatewayDirection::agent_initiated_bidirectional};
};

bool is_valid_gateway_config(const AgentGatewayConfig& config);
bool is_allowed_server_message(ServerMessageType message_type);

}  // namespace ipms::agent
