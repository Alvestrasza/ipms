#include "ipms/agent/gateway_contract.hpp"
#include "ipms/agent/management_pack.hpp"

#include <cassert>

int main() {
  const ipms::agent::AgentGatewayConfig gateway{"management.example.invalid"};
  assert(gateway.port == 9419);
  assert(ipms::agent::is_valid_gateway_config(gateway));
  assert(ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::management_pack_assignment));
  assert(ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::inventory_collection_request));
  assert(ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::agent_update_manifest));
  assert(ipms::agent::is_allowed_server_message(ipms::agent::ServerMessageType::certificate_rotation));
  const auto& packs = ipms::agent::builtin_management_packs();
  assert(packs.size() == 2);
  assert(packs[0].id == "windows-server-core");
  assert(packs[1].id == "hyper-v-host");
  assert(packs[1].dependencies.size() == 1);
  assert(packs[1].dependencies[0] == "windows-server-core");
  for (const auto& pack : packs) assert(ipms::agent::is_valid_pack_assignment(pack));
}
