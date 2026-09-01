#include "ipms/agent/configuration.hpp"
#include "ipms/agent/gateway_contract.hpp"
#include "ipms/agent/management_pack.hpp"

#include <algorithm>

int main() {
  const ipms::agent::AgentConfiguration configuration{L"management.example.invalid", 9419, ipms::agent::TrustMode::ipms_managed};
  if (!ipms::agent::is_valid_agent_configuration(configuration)) return 1;
  if (ipms::agent::trust_mode_name(ipms::agent::TrustMode::external_issuing_ca) != L"external_issuing_ca") return 2;
  if (ipms::agent::parse_trust_mode(L"external_certificates") != ipms::agent::TrustMode::external_certificates) return 3;
  const ipms::agent::AgentGatewayConfig gateway{"management.example.invalid"};
  if (gateway.port != 9419) return 4;
  if (!ipms::agent::is_valid_gateway_config(gateway)) return 5;
  if (!ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::management_pack_assignment)) return 6;
  if (!ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::inventory_collection_request)) return 7;
  if (!ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::agent_update_manifest)) return 8;
  if (!ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::certificate_rotation)) return 9;
  const auto& packs = ipms::agent::builtin_management_packs();
  if (packs.size() != 2) return 10;
  if (packs[0].id != "windows-server-core") return 11;
  if (packs[1].id != "hyper-v-host") return 12;
  if (packs[1].dependencies.size() != 1) return 13;
  if (packs[1].dependencies[0] != "windows-server-core") return 14;
  for (const auto& pack : packs) if (!ipms::agent::is_valid_pack_assignment(pack)) return 15;
  if (std::find(
          packs[0].capabilities.begin(),
          packs[0].capabilities.end(),
          "windows.roles-features") == packs[0].capabilities.end()) return 16;
  return 0;
}
