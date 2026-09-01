#include "ipms/agent/gateway_contract.hpp"

namespace ipms::agent {

bool is_valid_gateway_config(const AgentGatewayConfig& config) {
  return !config.hostname.empty() && config.port != 0 &&
         config.direction == GatewayDirection::agent_initiated_bidirectional;
}

bool is_allowed_server_message(ServerMessageType message_type) {
  switch (message_type) {
    case ServerMessageType::management_pack_assignment:
    case ServerMessageType::inventory_collection_request:
    case ServerMessageType::agent_update_manifest:
    case ServerMessageType::certificate_rotation:
      return true;
  }
  return false;
}

}  // namespace ipms::agent
