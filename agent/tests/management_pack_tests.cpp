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
  if (packs.size() != 4) return 10;
  const auto hyperv = std::find_if(
      packs.begin(), packs.end(), [](const auto& pack) { return pack.id == "hyper-v-host"; });
  const auto windows = std::find_if(
      packs.begin(), packs.end(), [](const auto& pack) { return pack.id == "windows-server-core"; });
  const auto software = std::find_if(
      packs.begin(), packs.end(), [](const auto& pack) { return pack.id == "windows-software"; });
  const auto linux = std::find_if(
      packs.begin(), packs.end(), [](const auto& pack) { return pack.id == "linux-core"; });
  if (windows == packs.end() || hyperv == packs.end() || software == packs.end() || linux == packs.end()) return 11;
  if (hyperv->dependencies.size() != 1 || hyperv->dependencies[0] != "windows-server-core") return 12;
  if (software->dependencies.size() != 1 || software->dependencies[0] != "windows-server-core") return 13;
  for (const auto& pack : packs) if (!ipms::agent::is_valid_pack_assignment(pack)) return 15;
  if (std::find(
          windows->capabilities.begin(),
          windows->capabilities.end(),
          "windows.roles-features") == windows->capabilities.end()) return 16;
  return 0;
}
