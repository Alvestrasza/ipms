#include "ipms/agent/management_pack.hpp"

#include <cassert>

int main() {
  const auto& packs = ipms::agent::builtin_management_packs();
  assert(packs.size() == 2);
  assert(packs[0].id == "windows-server-core");
  assert(packs[1].id == "hyper-v-host");
  assert(packs[1].dependencies.size() == 1);
  assert(packs[1].dependencies[0] == "windows-server-core");
  for (const auto& pack : packs) assert(ipms::agent::is_valid_pack_assignment(pack));
}
