#include "ipms/agent/management_pack.hpp"

#include <algorithm>

namespace ipms::agent {

const std::vector<ManagementPack>& builtin_management_packs() {
  static const std::vector<ManagementPack> packs{
      {"windows-server-core", "0.1.16", AccessMode::read_inventory, {}, {"windows.os", "windows.hardware", "windows.storage", "windows.network"}},
      {"hyper-v-host", "0.1.16", AccessMode::read_inventory, {"windows-server-core"}, {"hyperv.host", "hyperv.virtual-machines", "hyperv.network"}},
  };
  return packs;
}

bool is_valid_pack_assignment(const ManagementPack& pack) {
  if (pack.id.empty() || pack.version.empty() || pack.access_mode != AccessMode::read_inventory) return false;
  return std::all_of(pack.capabilities.begin(), pack.capabilities.end(), [](std::string_view capability) { return !capability.empty(); });
}

}  // namespace ipms::agent
