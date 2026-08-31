#pragma once

#include <string_view>
#include <vector>

namespace ipms::agent {

enum class AccessMode { read_inventory, management };

struct ManagementPack {
  std::string_view id;
  std::string_view version;
  AccessMode access_mode;
  std::vector<std::string_view> dependencies;
  std::vector<std::string_view> capabilities;
};

const std::vector<ManagementPack>& builtin_management_packs();
bool is_valid_pack_assignment(const ManagementPack& pack);

}  // namespace ipms::agent
