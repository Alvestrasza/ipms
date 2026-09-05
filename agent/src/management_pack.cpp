#include "ipms/agent/management_pack.hpp"

#include <algorithm>

namespace ipms::agent {

const std::vector<ManagementPack>& builtin_management_packs() {
  static const std::vector<ManagementPack> packs{
      {"windows-server-core", "0.2.12", AccessMode::read_inventory, {}, {"windows.os", "windows.hardware", "windows.storage", "windows.network", "windows.roles-features"}},
      {"windows-software", "0.2.12", AccessMode::read_inventory, {"windows-server-core"}, {"windows.software", "windows.update-posture"}},
      {"hyper-v-host", "0.2.25", AccessMode::management, {"windows-server-core"}, {"hyperv.host", "hyperv.virtual-machines", "hyperv.network", "hyperv.vm.lifecycle", "hyperv.vm.console"}},
      {"linux-core", "0.2.12", AccessMode::read_inventory, {}, {"linux.os", "linux.hardware", "linux.storage", "linux.network", "linux.software", "linux.update-posture"}},
  };
  return packs;
}

bool is_valid_pack_assignment(const ManagementPack& pack) {
  if (pack.id.empty() || pack.version.empty()) return false;
  if (pack.access_mode == AccessMode::management && pack.id != "hyper-v-host") return false;
  return std::all_of(pack.capabilities.begin(), pack.capabilities.end(), [](std::string_view capability) { return !capability.empty(); });
}

}  // namespace ipms::agent
